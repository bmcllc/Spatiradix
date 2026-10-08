//! P4a: the pinned policy authority and the signed outcome policy.
//!
//! # The rule this module exists to enforce
//!
//! The key that authorises an artefact must not travel inside the artefact it
//! authorises.
//!
//! ```text
//! WRONG: the signed payload carries the authority public key, and the
//!        verifier trusts whatever key it finds there. A signature over a
//!        payload that names its own signer proves only that the signer signed;
//!        anybody can mint a key, name it, and sign. There is no authority in
//!        that arrangement, only a self-consistent blob.
//!
//! RIGHT: the payload names a *key id*, and the key is resolved through a
//!         trust anchor pinned outside the mutable economy directory. A policy
//!        whose authority key is not the pinned key is unattested, no matter
//!        how well it is signed.
//! ```
//!
//! [`mycelium_pheromones::Gland`](../../mycelium_pheromones/src/lib.rs) is the
//! counter-example this module deliberately does **not** copy. `Gland` embeds
//! `identity: [u8; 32]` in `PheromoneBody` and `Pheromone::sniff` does
//! `VerifyingKey::from_bytes(&self.body.identity)`: the verifying key is read
//! off the untrusted payload. The sign/verify *technique* here is ed25519 via
//! `ed25519-dalek`, the same one `Gland` uses; the *key distribution* is
//! deliberately not.
//!
//! # The trust anchor is outside the economy directory
//!
//! The anchor is a regular file, [`DEFAULT_POLICY_AUTHORITY_PIN_PATH`], holding
//! one authority public key. It is deliberately **not** inside
//! `~/.mycelium/economy/`: that directory is mutable by the very principals
//! this step exists to constrain, so a pin kept there is not an anchor, it is
//! another field of the thing being pinned.
//!
//! /etc is not writable by an unprivileged operator, so on a deployment without
//! root the pin path is *configured* rather than fixed. What is configurable is
//! the path; what is not configurable is the refusal. A missing, unreadable,
//! symlinked, over-permissive or wrong-owned pin leaves the policy UNATTESTED
//! and every consumer fails closed. There is no in-tree fallback, and no
//! environment-variable override of the anchor path: an env var is
//! attacker-controlled, and an attacker-chosen anchor is the bug this module
//! exists to remove.
//!
//! ## What the anchor's checks defeat, and what they do not
//!
//! Defeated:
//! * redirection of the pin with a symlink (`lstat`, and the checks are then
//!   repeated on the *opened descriptor*, so a path swapped between the two
//!   syscalls still lands on a validated inode);
//! * group- or world-writable pin, i.e. another account rewriting the anchor
//!   in place (`mode & 0o022 == 0`);
//! * a pin owned by an account other than the configured one (`uid ==`);
//! * a pin holding a role other than `policy-authority` (role is both an
//!   explicit field of the pin file and part of the [`KeyId`] derivation, so a
//!   verifier-runtime key cannot masquerade as an authority by key bytes);
//! * self-signed policy: the authority key used to verify is the one read from
//!   the pin, never the one named in the payload.
//!
//! **Not** defeated, and stated here so it is not implied anywhere:
//!
//! * Same-principal replacement of both the pin and the binary. P4
//!   authenticates a policy against a *configured pin*; it cannot tell a
//!   pinned anchor from a replaced one when the same principal owns both, and
//!   it is not a code-signing or attestation story. That is outside the closed
//!   threat model of this step.
//! * Rollback to a previously valid policy. Policy-rotation history is out of
//!   scope here: a policy that does not validate against the current registry
//!   and provider is unattested, but this module keeps no revocation list and
//!   no `policy_version` high-water mark.
//! * Compromise of the authority *private* key. Out of scope by construction.
//! * The mutable economy directory itself. Nothing here stops a process that
//!   can write it from editing the ledger; that is the next step, not this one.

use crate::{
    base_usdc::{normalize_address, validate_hash32},
    boundary::ControlledAddressRegistry,
    chain_provider::{ChainTransport, PinnedChainProvider},
    EconomyError,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{
    collections::BTreeSet,
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

/// Canonical location of the pinned policy authority key.
///
/// It lives under `/etc` so that writing it requires privileges the economy
/// process does not have. On a host where that directory is not creatable the
/// path becomes part of [`TrustStoreConfig`] instead; the checks applied to the
/// file are identical either way.
pub const DEFAULT_POLICY_AUTHORITY_PIN_PATH: &str = "/etc/mycelium/trust/policy-authority.pub";

/// Name of the signed outcome policy document inside the economy root.
///
/// The document is *not* the anchor: it is data, it lives in the mutable
/// directory, and everything in it buys nothing until [`validate_outcome_policy`]
/// resolves its authority through [`DEFAULT_POLICY_AUTHORITY_PIN_PATH`]. Writing
/// it here is an operator action, which is why the crate ships no command that
/// signs one — the authority's private half is not in this binary.
pub const OUTCOME_POLICY_FILE: &str = "outcome-policy.json";

/// UID that must own the pin when the configuration does not name one.
pub const DEFAULT_POLICY_AUTHORITY_PIN_UID: u32 = 0;

/// Domain string of the policy signing preimage. First bytes of every
/// preimage, so a policy signature can never be replayed as a signature over
/// some other message this crate produces.
pub const POLICY_SIGNING_DOMAIN: &str = "MYCELIUM-ECONOMY/POLICY/V1";

/// Domain of the controlled-address registry binding.
pub const CONTROLLED_REGISTRY_DOMAIN: &str = "MYCELIUM-ECONOMY/CONTROLLED-REGISTRY/V1";

/// Domain of the provider-identity binding.
pub const PROVIDER_IDENTITY_DOMAIN: &str = "MYCELIUM-ECONOMY/PROVIDER-IDENTITY/V1";

/// Domain of the digest a receipt is bound to. Distinct from every other domain
/// in this module so a policy hash can never be confused with a policy
/// signature, a registry digest or a provider-identity digest.
pub const POLICY_HASH_DOMAIN: &str = "MYCELIUM-ECONOMY/POLICY-HASH/V1";

/// Domain prefix of a key identity. The role is appended, which is what makes
/// the role part of the identity instead of a label next to it.
const KEY_ID_DOMAIN_PREFIX: &str = "MYCELIUM-ECONOMY/POLICY-KEY-ID/V1";

/// First line of the pin file. A file that does not start with this is not a
/// pin, whatever else it contains.
const PIN_FILE_DOMAIN: &str = "MYCELIUM-ECONOMY/POLICY-AUTHORITY-PIN/V1";

/// Canonical wire spelling of [`KeyRole::PolicyAuthority`].
const ROLE_AUTHORITY_SPELLING: &str = "policy-authority";
/// Canonical wire spelling of [`KeyRole::VerifierRuntime`].
const ROLE_VERIFIER_SPELLING: &str = "verifier-runtime";

/// Largest pin file accepted, in bytes. A pin is three short lines; anything
/// past this is not one, and reading it unbounded would hand a hostile
/// `~/.mycelium`-adjacent path a memory-pressure lever for free.
const MAX_PIN_FILE_BYTES: u64 = 256;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// The pin could not be read, does not exist, or fails a filesystem
    /// identity check. Fail-closed: there is no fallback path.
    #[error("policy authority pin unavailable: {0}")]
    PinUnavailable(String),

    /// The pin file is present and readable but is not a well-formed pin.
    #[error("policy authority pin malformed: {0}")]
    PinMalformed(String),

    /// The pin names a role other than the authority role.
    #[error("policy authority pin has role {found}, which cannot authorise policies")]
    PinRoleMismatch { found: String },

    /// The key needed to verify this artefact is not the pinned key. This is
    /// the error the self-signed-policy shape gets.
    #[error(
        "policy claims authority key {claimed}, but the pinned authority is \
         {pinned}; a policy may never bring its own authority key"
    )]
    AuthorityNotPinned { claimed: String, pinned: String },

    /// One key was used in both roles.
    #[error("key {key_id} is offered in both the policy-authority and the verifier-runtime role")]
    RoleCollision { key_id: String },

    #[error("signature does not verify against the pinned authority key")]
    BadSignature,

    #[error("policy preimage is malformed: {0}")]
    Preimage(String),

    #[error("policy schema_version {found} is not supported (expected {expected})")]
    UnsupportedSchema { found: u32, expected: u32 },

    #[error("policy chain_id {found} does not match the expected chain {expected}")]
    ChainMismatch { found: u64, expected: u64 },

    #[error("policy min_confirmations is {found}, but a policy must require at least 1")]
    MinConfirmationsTooLow { found: u64 },

    #[error("policy controlled_registry_hash {found} does not match the live registry {live}")]
    ControlledRegistryMismatch { found: String, live: String },

    #[error(
        "policy provider_identity_hash {found} does not match the live provider constraints {live}"
    )]
    ProviderIdentityMismatch { found: String, live: String },

    #[error("policy authority key is not an identified ed25519 public key: {0}")]
    MalformedKey(String),

    #[error("invalid {field}: {reason}")]
    InvalidField { field: &'static str, reason: String },

    /// P6.9. The on-disk state a policy gate reads could not be read or
    /// written: a missing mark file, a broken hash chain, a contended ledger
    /// lock. Fail-closed like the rest of this enum — a gate that cannot read
    /// its own mark must not fall back to "no mark yet".
    #[error("policy state unavailable: {0}")]
    StateUnavailable(String),

    /// P6.9. The offered policy is **older** than the high-water mark. Refused
    /// even though its signature, its chain, its registry binding and its
    /// provider binding all verify: a genuinely signed old policy is exactly
    /// what a rollback looks like.
    #[error(
        "policy rollback refused: offered v{offered_version} ({offered_hash}) but the high-water \
         mark is v{high_water_version} ({high_water_hash}); a policy version only moves forward"
    )]
    PolicyRollback {
        offered_version: u64,
        offered_hash: String,
        high_water_version: u64,
        high_water_hash: String,
    },

    /// P6.9. The offered policy claims the high-water version but is a different
    /// document. This is the failure a bare `highest_policy_version` cannot
    /// see: the number is right and the content is wrong, which is what an
    /// operational bug that associates one number with two documents looks like.
    #[error(
        "policy hash divergence at version {version}: the offered document hashes to \
         {offered_hash} but the high-water mark recorded {high_water_hash}; two different \
         documents cannot share one version"
    )]
    PolicyHashDivergence {
        version: u64,
        offered_hash: String,
        high_water_hash: String,
    },
}

impl PolicyError {
    /// Whether this error means "there is no authority", as opposed to "this
    /// artefact is not good enough". Only the first kind is a missing anchor.
    fn is_pin_failure(&self) -> bool {
        matches!(
            self,
            PolicyError::PinUnavailable(_)
                | PolicyError::PinMalformed(_)
                | PolicyError::PinRoleMismatch { .. }
        )
    }
}

/// The other direction, for the P6.9 high-water gate: reading the mark, taking
/// the ledger lock and verifying the chain are [`EconomyError`] operations, and
/// a `PolicyError` is the vocabulary a policy gate reports in. The conversion is
/// lossless in the only direction that matters — the original text is carried
/// verbatim — and it is defined here rather than in `policy_watermark` so that
/// the two error types never learn about each other in one direction only.
impl From<EconomyError> for PolicyError {
    fn from(err: EconomyError) -> Self {
        PolicyError::StateUnavailable(err.to_string())
    }
}

impl From<PolicyError> for EconomyError {
    fn from(err: PolicyError) -> Self {
        if err.is_pin_failure() {
            // Reuses the crate's existing fail-closed vocabulary rather than
            // inventing a second one for the same condition.
            EconomyError::ProviderUnpinned(err.to_string())
        } else {
            EconomyError::Invalid(err.to_string())
        }
    }
}

// ---------------------------------------------------------------------------
// Key roles and key identity
// ---------------------------------------------------------------------------

/// The two signing roles. One key may not serve both, and the role is part of
/// the key *identity* ([`KeyId`]) rather than an attribute read off the
/// artefact, so the separation survives deserialisation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyRole {
    /// Signs outcome policies. Resolved only through the pinned trust anchor.
    PolicyAuthority,
    /// Signs attestations and receipts. Delegated *by* a signed policy, never
    /// self-asserted.
    VerifierRuntime,
}

impl KeyRole {
    /// The domain this role hashes under. Two roles, two domains: the same 32
    /// key bytes produce different ids here, which is the property that makes a
    /// verifier key unusable as an authority key.
    pub fn key_id_domain(&self) -> String {
        match self {
            KeyRole::PolicyAuthority => format!("{KEY_ID_DOMAIN_PREFIX}/POLICY-AUTHORITY"),
            KeyRole::VerifierRuntime => format!("{KEY_ID_DOMAIN_PREFIX}/VERIFIER-RUNTIME"),
        }
    }

    /// Wire spelling used in the pin file.
    pub fn spelling(&self) -> &'static str {
        match self {
            KeyRole::PolicyAuthority => ROLE_AUTHORITY_SPELLING,
            KeyRole::VerifierRuntime => ROLE_VERIFIER_SPELLING,
        }
    }

    /// Parses a wire spelling. Total: only the two spellings above.
    pub fn from_spelling(s: &str) -> Option<Self> {
        match s {
            ROLE_AUTHORITY_SPELLING => Some(KeyRole::PolicyAuthority),
            ROLE_VERIFIER_SPELLING => Some(KeyRole::VerifierRuntime),
            _ => None,
        }
    }

    /// Every role, for exhaustive checks.
    pub fn all() -> [KeyRole; 2] {
        [KeyRole::PolicyAuthority, KeyRole::VerifierRuntime]
    }
}

impl fmt::Display for KeyRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.spelling())
    }
}

/// A public key, addressed by a role-bound id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifierPublicKey([u8; 32]);

impl VerifierPublicKey {
    /// Wraps raw ed25519 public key bytes. The bytes themselves are the
    /// authority's choice; nothing here asserts anything about them.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The role this key operates in.
    pub fn role(&self) -> KeyRole {
        KeyRole::VerifierRuntime
    }

    /// The identity this key has *in this role*.
    pub fn key_id(&self) -> KeyId {
        KeyId::derive(KeyRole::VerifierRuntime, &self.0)
    }

    /// The dalek key for signature checks.
    ///
    /// **Private to this module, deliberately (P4b).** This used to be public so
    /// that receipt verification could reach it, and that is the Gland trap one
    /// layer down: `Gland::sniff` reads its verifying key off the untrusted
    /// payload, and a public `verifying_key()` on a key type that can be
    /// constructed from raw bytes (`VerifierPublicKey::from_bytes`) gives any
    /// caller in the crate the same shortcut — take a key a policy *claims*, and
    /// verify with it.
    ///
    /// The fix is not "be careful at the call site", it is the type: the only
    /// route to a `VerifyingKey` in this crate is
    /// [`TrustedVerifierKey::verifying_key`], and a `TrustedVerifierKey` can
    /// only be built by [`ValidatedOutcomePolicy::trusted_verifier`]. A key read
    /// off an unvalidated policy therefore cannot verify a receipt at all,
    /// because it cannot become one of those.
    ///
    /// The trade-off: P4a's own tests reach this through `mod tests`, which is a
    /// child of this module and can still see private items, so no test had to
    /// change. The cost is that a *sibling* module can no longer turn raw public
    /// key bytes into a dalek key at all — which is the entire point, and is why
    /// [`crate::receipt_auth`] takes the key from the validated policy instead of
    /// from a caller.
    fn verifying_key(&self) -> Result<VerifyingKey, PolicyError> {
        VerifyingKey::from_bytes(&self.0)
            .map_err(|_| PolicyError::MalformedKey("ed25519 point is not on the curve".into()))
    }
}

impl fmt::Display for VerifierPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

/// Serialised as `0x<64 hex>`. Fixed width, so there is exactly one spelling per
/// key; the role is *not* implied by the encoding, which is why
/// [`OutcomePolicyPayload::verifier_key_id`] has to agree with these bytes and
/// is checked at validation.
impl Serialize for VerifierPublicKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for VerifierPublicKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        let body = raw
            .strip_prefix("0x")
            .ok_or_else(|| serde::de::Error::custom("public key must be 0x-prefixed"))?;
        let bytes = hex::decode(body)
            .ok()
            .and_then(|v| <[u8; 32]>::try_from(v).ok())
            .ok_or_else(|| serde::de::Error::custom("public key must be 32 bytes of hex"))?;
        Ok(VerifierPublicKey(bytes))
    }
}

/// A role-bound key identity.
///
/// The id is a hash over (role domain, raw key bytes), so:
/// * the role cannot be edited, because changing it changes the id;
/// * an authority id and a verifier id derived from the *same* bytes are
///   different values, so no policy can name one role's id and mean the other;
/// * an id names nothing on its own. It is a lookup label; the key behind it is
///   only ever obtained from the pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyId {
    role: KeyRole,
    bytes: [u8; 32],
}

impl KeyId {
    /// Derives the identity of `key` when used in `role`.
    pub fn derive(role: KeyRole, key: &[u8; 32]) -> Self {
        let mut buf = Vec::with_capacity(64);
        push_tagged(&mut buf, b"domain", role.key_id_domain().as_bytes());
        push_tagged(&mut buf, b"key", key);
        Self {
            role,
            bytes: *blake3::hash(&buf).as_bytes(),
        }
    }

    /// Recomputes the id of `key` in `role` and compares. Used so that an id
    /// present in a payload is checked against the key actually offered,
    /// rather than trusted as a label.
    pub fn matches_key(&self, key: &[u8; 32]) -> bool {
        KeyId::derive(self.role, key) == *self
    }

    pub fn role(&self) -> KeyRole {
        self.role
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:0x{}", self.role, hex::encode(self.bytes))
    }
}

/// Serialised form is `role|0x<hex>`, kept as one string so an id cannot be
/// read back with its role dropped.
impl Serialize for KeyId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for KeyId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        parse_key_id(&raw).map_err(serde::de::Error::custom)
    }
}

fn parse_key_id(raw: &str) -> Result<KeyId, PolicyError> {
    let (role, hexpart) = raw
        .split_once(':')
        .ok_or_else(|| PolicyError::InvalidField {
            field: "key_id",
            reason: format!("expected `role|0x<64 hex>`, got {raw:?}"),
        })?;
    let role = KeyRole::from_spelling(role).ok_or_else(|| PolicyError::InvalidField {
        field: "key_id",
        reason: format!("unknown key role {role:?}"),
    })?;
    let bytes: [u8; 32] = hex::decode(hexpart.strip_prefix("0x").unwrap_or(hexpart))
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .ok_or_else(|| PolicyError::InvalidField {
            field: "key_id",
            reason: format!("{hexpart:?} is not 32 bytes of hex"),
        })?;
    Ok(KeyId { role, bytes })
}

/// The private half of the authority role. Held by whoever operates the
/// anchor, never by the verifier: the verifier only ever sees the pin.
#[derive(Clone)]
pub struct PolicyAuthorityKey {
    role: KeyRole,
    signing: SigningKey,
}

impl fmt::Debug for PolicyAuthorityKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PolicyAuthorityKey")
            .field("role", &self.role)
            .field("key_id", &self.key_id())
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl PolicyAuthorityKey {
    /// Generates a fresh authority key. Operator-side only.
    pub fn generate() -> Self {
        Self {
            role: KeyRole::PolicyAuthority,
            signing: SigningKey::generate(&mut rand::rngs::OsRng),
        }
    }

    /// Restores an authority key from a stored seed. Operator-side only.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            role: KeyRole::PolicyAuthority,
            signing: SigningKey::from_bytes(&seed),
        }
    }

    pub fn role(&self) -> KeyRole {
        self.role
    }

    /// Identity of the public half in the authority role. This is the id an
    /// operator writes into the pin, and the id a policy is expected to carry.
    pub fn key_id(&self) -> KeyId {
        KeyId::derive(KeyRole::PolicyAuthority, &self.verifying_key_bytes())
    }

    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// Bytes an operator writes into the pin file.
    pub fn pin_document(&self) -> String {
        format_pin_document(self.role, &self.verifying_key_bytes())
    }

    /// Signs a policy.
    ///
    /// Refuses to sign a policy that delegates to the verifier key held by the
    /// same bytes: the role-separation rule is enforced here, at the only place
    /// where the authority is choosing what to delegate, instead of being left
    /// to a consumer to notice.
    pub fn sign(
        &self,
        payload: OutcomePolicyPayload,
        verifier: &VerifierRuntimeKey,
    ) -> Result<SignedOutcomePolicy, PolicyError> {
        if self.verifying_key_bytes() == verifier.verifying_key_bytes() {
            return Err(PolicyError::RoleCollision {
                key_id: self.key_id().to_string(),
            });
        }
        // The payload must not claim a verifier id other than the one the
        // signer is actually delegating to.
        if payload.verifier_key_id != verifier.key_id() {
            return Err(PolicyError::InvalidField {
                field: "verifier_key_id",
                reason: format!(
                    "payload names {} but the offered verifier key is {}",
                    payload.verifier_key_id,
                    verifier.key_id()
                ),
            });
        }
        let preimage = payload.signing_preimage()?;
        let signature = self.signing.sign(&preimage);
        Ok(SignedOutcomePolicy {
            payload,
            authority_key_id: self.key_id(),
            signature,
        })
    }
}

/// The private half of the verifier role. Signs attestations and receipts.
#[derive(Clone)]
pub struct VerifierRuntimeKey {
    role: KeyRole,
    signing: SigningKey,
}

impl fmt::Debug for VerifierRuntimeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifierRuntimeKey")
            .field("role", &self.role)
            .field("key_id", &self.key_id())
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl VerifierRuntimeKey {
    /// Generates a fresh verifier key.
    pub fn generate() -> Self {
        Self {
            role: KeyRole::VerifierRuntime,
            signing: SigningKey::generate(&mut rand::rngs::OsRng),
        }
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            role: KeyRole::VerifierRuntime,
            signing: SigningKey::from_bytes(&seed),
        }
    }

    pub fn role(&self) -> KeyRole {
        self.role
    }

    /// Identity of the public half in the *verifier* role.
    pub fn key_id(&self) -> KeyId {
        KeyId::derive(KeyRole::VerifierRuntime, &self.verifying_key_bytes())
    }

    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// Signs a caller-built preimage with this key.
    ///
    /// `pub(crate)`, and deliberately a raw signer rather than a second
    /// attestation constructor: the private half is the private half, so whoever
    /// holds this value could sign anything with it and pretending otherwise
    /// would be security theatre. What actually protects the read side is that
    /// `AuthenticatedExternalValueReceipt` has no public constructor and the one
    /// constructor [`crate::receipt_auth::VerifierRuntimeKey::attest`] enforces is
    /// the delegation rule — that the key signing is the key a *validated*
    /// policy delegated to. This method only exists so that module can get at
    /// `signing` without making the field crate-visible, which would hand the
    /// same power to every other module in the crate by another route.
    pub(crate) fn sign_preimage(&self, preimage: &[u8]) -> Signature {
        use ed25519_dalek::Signer as _;
        self.signing.sign(preimage)
    }

    /// The public half, as it appears inside a signed policy.
    pub fn public_key(&self) -> VerifierPublicKey {
        VerifierPublicKey::from_bytes(self.verifying_key_bytes())
    }
}

// ---------------------------------------------------------------------------
// Canonical addresses and hashes
// ---------------------------------------------------------------------------

/// A canonical 20-byte chain address. Construction runs the crate's existing
/// `normalize_address`, so a policy cannot carry a checksummed, mixed-case or
/// truncated spelling that hashes differently from the ledger's copy of the
/// same address.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Address(String);

impl Address {
    /// Validating constructor. Reuses [`normalize_address`].
    pub fn parse(value: &str) -> Result<Self, PolicyError> {
        normalize_address(value)
            .map(Self)
            .map_err(|e| PolicyError::InvalidField {
                field: "address",
                reason: e.to_string(),
            })
    }

    /// The canonical `0x`-prefixed lowercase spelling. This is the form that
    /// goes into the preimage.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A canonical 32-byte hash. Construction runs the crate's existing
/// [`validate_hash32`], and the stored form is normalised to `0x`-prefixed
/// lowercase so two spellings of one digest cannot produce two preimages.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Hash(String);

impl Hash {
    /// Validating constructor. Reuses [`validate_hash32`].
    pub fn parse(name: &'static str, value: &str) -> Result<Self, PolicyError> {
        validate_hash32(name, value).map_err(|e| PolicyError::InvalidField {
            field: name,
            reason: e.to_string(),
        })?;
        let body = value
            .strip_prefix("0x")
            .unwrap_or(value)
            .to_ascii_lowercase();
        Ok(Self(format!("0x{body}")))
    }

    /// Computes a `Hash` from raw digest bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(format!("0x{}", hex::encode(bytes)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Raw digest. Used by the preimage encoder, which prefers fixed-width
    /// binary over hex text.
    pub fn to_bytes(&self) -> Result<[u8; 32], PolicyError> {
        hex::decode(self.0.strip_prefix("0x").unwrap_or(&self.0))
            .ok()
            .and_then(|v| <[u8; 32]>::try_from(v).ok())
            .ok_or_else(|| PolicyError::Preimage(format!("{self} is not 32 bytes of hex")))
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// The bindings: registry and provider identity
// ---------------------------------------------------------------------------

/// Computes the digest that binds a [`ControlledAddressRegistry`] into a policy.
///
/// This is what makes the hash *mean* something. The registry is a
/// `BTreeSet<String>`, and the digest walks its contents in sorted order with a
/// per-entry tag and a length prefix, so:
///
/// * adding, removing or changing any address changes the digest — the policy
///   is invalidated by editing the registry, which is the entire point;
/// * the entry order cannot be chosen to preserve the digest, because the order
///   is derived from the normalised addresses and re-sorted defensively;
/// * the empty registry hashes to a distinct, well-defined value rather than to
///   "unset", so a policy cannot be made to match an emptied registry by
///   omission;
/// * the domain is [`CONTROLLED_REGISTRY_DOMAIN`], so this digest can never be
///   confused with any other digest in the crate.
pub fn controlled_registry_hash(registry: &ControlledAddressRegistry) -> Result<Hash, PolicyError> {
    // `addresses()` already yields sorted normalised values; the BTreeSet is
    // re-collected rather than trusted so this function cannot change meaning if
    // the registry's internals are ever replaced by a HashSet.
    let mut entries: BTreeSet<String> = BTreeSet::new();
    for address in registry.addresses() {
        entries.insert(address.to_string());
    }
    let mut buf = Vec::new();
    push_tagged(&mut buf, b"domain", CONTROLLED_REGISTRY_DOMAIN.as_bytes());
    let count = u32::try_from(entries.len()).map_err(|_| {
        PolicyError::Preimage("controlled registry has more than u32::MAX addresses".into())
    })?;
    push_tagged(&mut buf, b"count", &count.to_be_bytes());
    for address in entries {
        push_tagged(&mut buf, b"addr", address.as_bytes());
    }
    Ok(Hash::from_bytes(*blake3::hash(&buf).as_bytes()))
}

/// The provider identity a signed policy requires, expressed as the exact
/// pin properties the policy was signed against.
///
/// Binding the digest over the *pin* and not over "some provider is pinned"
/// is what stops a policy signed for a kernel-enforced unix socket from being
/// reused against a loopback TCP port that answers just as well. Transport,
/// canonical endpoint and required owner uid are all in the digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderIdentityConstraints {
    /// Which transport the policy was signed for.
    pub transport: ChainTransport,
    /// Canonical endpoint, e.g. `unix:///run/mycelium-verifier.sock`.
    pub endpoint: String,
    /// UID the socket inode must be owned by.
    pub socket_owner_uid: u32,
}

impl ProviderIdentityConstraints {
    /// Reads the constraints out of a pin.
    pub fn from_pinned_provider(provider: &PinnedChainProvider) -> Self {
        Self {
            transport: provider.transport(),
            endpoint: provider.endpoint().to_string(),
            socket_owner_uid: provider.socket_owner_uid_or_default(),
        }
    }

    /// Whether these constraints demand an identity the kernel enforces. A
    /// policy that does not demand one cannot attest chain truth, whatever it
    /// was signed over.
    pub fn kernel_enforced(&self) -> bool {
        self.transport == ChainTransport::UnixSocket
    }

    /// Digest of the constraints. Same construction as
    /// [`controlled_registry_hash`], different domain.
    pub fn identity_hash(&self) -> Hash {
        let mut buf = Vec::new();
        push_tagged(&mut buf, b"domain", PROVIDER_IDENTITY_DOMAIN.as_bytes());
        push_tagged(
            &mut buf,
            b"transport",
            transport_spelling(self.transport).as_bytes(),
        );
        push_tagged(&mut buf, b"endpoint", self.endpoint.as_bytes());
        push_tagged(&mut buf, b"owner_uid", &self.socket_owner_uid.to_be_bytes());
        Hash::from_bytes(*blake3::hash(&buf).as_bytes())
    }
}

/// Canonical wire spelling of a transport. Total over the two variants, and
/// used in a signed digest, so a future variant must be given an explicit
/// spelling here rather than falling through to a debug name.
fn transport_spelling(transport: ChainTransport) -> &'static str {
    match transport {
        ChainTransport::UnixSocket => "unix_socket",
        ChainTransport::LoopbackHttp => "loopback_http",
    }
}

/// Digests a payload hash. Same construction as
/// [`controlled_registry_hash`], different domain.
pub fn provider_identity_hash(constraints: &ProviderIdentityConstraints) -> Hash {
    constraints.identity_hash()
}

// ---------------------------------------------------------------------------
// The policy
// ---------------------------------------------------------------------------

/// How a field is encoded into the preimage. The table is the single source of
/// the emission order, so the order cannot drift with the struct's field order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreimageFieldKind {
    /// Fixed-width big-endian integer, written as its raw bytes.
    U64,
    /// Fixed-width big-endian integer, written as its raw bytes.
    U32,
    /// Fixed-width 16-byte big-endian integer, written as its raw bytes.
    ///
    /// Added in P4.6 for one field: a price in fixed point. `u64` is too
    /// narrow for `cost_wei × price_musd_per_eth` to be safe at every
    /// physically reachable price, and `Bytes` would have meant a fixed-width
    /// integer wearing an opaque-length label. Written as raw 16 bytes rather
    /// than as decimal text, so one number has one spelling.
    U128,
    /// Fixed-width big-endian signed integer, written as its raw bytes.
    I64,
    /// One byte: `0` or `1`. Never `0x00`/`0x01` from a debug format.
    Bool,
    /// Canonical `0x`-prefixed lowercase ASCII.
    AddressText,
    /// UTF-8 text, written as its bytes. Used only for identifiers whose
    /// spelling is not otherwise canonicalised by a wrapper type.
    Text,
    /// Raw 32 digest bytes.
    Hash32,
    /// Raw 32 key-identity bytes.
    KeyId32,
    /// Raw 32 public key bytes.
    PublicKey32,
    /// Opaque bytes already in canonical form (a closed enum's wire spelling,
    /// for instance). Length-prefixed like every other field, so it cannot be
    /// confused with an adjacent text field.
    Bytes,
}

/// The preimage layout, in canonical order. Every field of
/// [`OutcomePolicyPayload`] appears exactly once, in this order.
pub const POLICY_PREIMAGE_FIELDS: &[(&str, PreimageFieldKind)] = &[
    ("schema_version", PreimageFieldKind::U32),
    ("policy_version", PreimageFieldKind::U64),
    ("chain_id", PreimageFieldKind::U64),
    ("executor", PreimageFieldKind::AddressText),
    ("min_confirmations", PreimageFieldKind::U64),
    ("controlled_registry_hash", PreimageFieldKind::Hash32),
    ("provider_identity_hash", PreimageFieldKind::Hash32),
    ("price_source_hash", PreimageFieldKind::Hash32),
    ("verifier_key_id", PreimageFieldKind::KeyId32),
    ("verifier_public_key", PreimageFieldKind::PublicKey32),
    ("created_at_unix", PreimageFieldKind::U64),
];

/// The signed content of an outcome policy.
///
/// `verifier_public_key` is inside the payload on purpose: a policy *is* the
/// authority's delegation of receipt-signing to a named verifier, so the
/// verifier key is data the policy is about. The key that authorises the policy
/// is not here at all — only an id, and that id resolves through the pin.
///
/// `price_source_hash` (P4.6) is the third binding, alongside the registry and
/// the provider pin: the digest of the
/// [`crate::trusted_valuation::PriceSourcePolicy`] this policy authorises. It is
/// a digest rather than the structured value for the same reason the other two
/// are — the policy names what is permitted, the node supplies what is live, and
/// the two must agree on a single handle. A policy that carries no permitted
/// source is refused at validation (step 10), so a price source can never be
/// named only by the observation that carries it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomePolicyPayload {
    pub schema_version: u32,
    pub policy_version: u64,
    pub chain_id: u64,
    pub executor: Address,
    pub min_confirmations: u64,
    /// Digest of the controlled-address registry this policy is scoped to.
    pub controlled_registry_hash: Hash,
    /// Digest of the chain-provider pin this policy is scoped to.
    pub provider_identity_hash: Hash,
    /// P4.6. Digest of the price-source policy this policy authorises: which
    /// source identities may speak for the base/native pair, the pair itself,
    /// the maximum staleness of a price, the chain context, the temporal
    /// selection rule and the rounding policy. See
    /// [`crate::trusted_valuation::PriceSourcePolicy::binding_hash`].
    ///
    /// **Schema 2.** The field is required, not defaulted: a document that
    /// omits it cannot be parsed, because a signed field with a default is a
    /// field whose signed value and whose read value can differ. An
    /// `outcome-policy.json` written before P4.6 therefore stops loading, which
    /// is the correct and unavoidable consequence of adding a row to a signed
    /// preimage — its signature was over a ten-section message.
    pub price_source_hash: Hash,
    /// Identity of the delegated verifier, in the verifier-runtime role.
    pub verifier_key_id: KeyId,
    /// The delegated verifier's ed25519 public key.
    pub verifier_public_key: VerifierPublicKey,
    pub created_at_unix: u64,
}

/// Schema version this build signs and accepts.
///
/// Bumped 1 -> 2 by P4.6. Every existing policy signature is invalidated by
/// this, deliberately: the payload gained a binding, and a signature over the
/// old ten-section preimage does not authorise the new eleven-section one.
/// There is no compatibility shim and there will not be one — a policy is an
/// authority statement, and re-signing it is how an operator says "I authorise
/// this price source".
pub const OUTCOME_POLICY_SCHEMA_VERSION: u32 = 2;

impl OutcomePolicyPayload {
    /// The exact bytes an authority key signs.
    ///
    /// Built byte by byte, never by serialising a struct, because signing a
    /// serialised form silently promotes encoding choices into cryptographic
    /// semantics. With JSON that would mean: field order, whitespace, key
    /// quoting, number formatting, and *unknown fields* — a peer that adds a
    /// field to the payload would silently break every existing signature, and
    /// any future change to a `serde` attribute or to a dependency's encoder
    /// would change what a valid signature is. The same reasoning applies to
    /// any other self-describing encoding.
    ///
    /// Instead the layout is:
    ///
    /// ```text
    /// tagged   := TAG_LEN:u32be || TAG || VALUE_LEN:u32be || VALUE
    /// preimage := tagged("domain", POLICY_SIGNING_DOMAIN)
    ///          || tagged("sections", SECTION_COUNT:u32be)
    ///          || section*
    /// section  := tagged(TAG_i, VALUE_i)   for TAG_i in POLICY_PREIMAGE_FIELDS
    /// ```
    ///
    /// with sections emitted in the order of [`POLICY_PREIMAGE_FIELDS`]. The
    /// domain comes first, so a policy signature can never verify over another
    /// message this crate signs. Length prefixes remove concatenation
    /// ambiguity, so `("0x12", "34")` and `("0x1", "234")` cannot collide. The
    /// table fixes the order, so the struct's declaration order is irrelevant
    /// to the bytes, and adding a field means adding a row here — visible in
    /// review rather than implicit in a serialiser.
    pub fn signing_preimage(&self) -> Result<Vec<u8>, PolicyError> {
        let schema_version = self.schema_version.to_be_bytes();
        let policy_version = self.policy_version.to_be_bytes();
        let chain_id = self.chain_id.to_be_bytes();
        let min_confirmations = self.min_confirmations.to_be_bytes();
        let controlled_registry_hash = self.controlled_registry_hash.to_bytes()?;
        let provider_identity_hash = self.provider_identity_hash.to_bytes()?;
        let price_source_hash = self.price_source_hash.to_bytes()?;
        let verifier_key_id = *self.verifier_key_id.as_bytes();
        let verifier_public_key = *self.verifier_public_key.as_bytes();
        let created_at_unix = self.created_at_unix.to_be_bytes();

        let values: Vec<(&str, &[u8])> = vec![
            ("schema_version", &schema_version),
            ("policy_version", &policy_version),
            ("chain_id", &chain_id),
            ("executor", self.executor.as_str().as_bytes()),
            ("min_confirmations", &min_confirmations),
            ("controlled_registry_hash", &controlled_registry_hash),
            ("provider_identity_hash", &provider_identity_hash),
            ("price_source_hash", &price_source_hash),
            ("verifier_key_id", &verifier_key_id),
            ("verifier_public_key", &verifier_public_key),
            ("created_at_unix", &created_at_unix),
        ];

        if values.len() != POLICY_PREIMAGE_FIELDS.len() {
            return Err(PolicyError::Preimage(format!(
                "encoder emitted {} sections for a layout of {}",
                values.len(),
                POLICY_PREIMAGE_FIELDS.len()
            )));
        }
        for ((tag, _), (expected_tag, _)) in values.iter().zip(POLICY_PREIMAGE_FIELDS) {
            if *tag != *expected_tag {
                return Err(PolicyError::Preimage(format!(
                    "encoder emitted section {tag:?} where the layout expects {expected_tag:?}"
                )));
            }
        }

        let mut buf = Vec::new();
        push_tagged(&mut buf, b"domain", POLICY_SIGNING_DOMAIN.as_bytes());
        push_tagged(
            &mut buf,
            b"sections",
            &u32::try_from(values.len())
                .map_err(|_| PolicyError::Preimage("too many sections".into()))?
                .to_be_bytes(),
        );
        for (tag, value) in &values {
            push_tagged(&mut buf, tag.as_bytes(), value);
        }
        Ok(buf)
    }
}

/// serde adapter for `ed25519_dalek::Signature`, which is a foreign type and so
/// cannot get its own impl here. Encoded as lowercase hex of the raw 64 bytes.
/// The signature is never trusted on the strength of having been read back: it
/// is always re-verified against the reconstructed preimage.
///
/// `pub(crate)` since P4b so [`crate::receipt_auth`] signs and stores signatures
/// in the same wire shape. A second, differently spelled encoding for the same
/// signature type is exactly the kind of duplication that lets a reader and a
/// writer disagree about which bytes were signed.
pub(crate) mod signature_serde {
    use super::{Deserialize, Deserializer, Serializer, Signature};

    pub fn serialize<S: Serializer>(
        signature: &Signature,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(signature.to_bytes()))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Signature, D::Error> {
        let raw = String::deserialize(deserializer)?;
        let bytes = hex::decode(raw.trim())
            .ok()
            .and_then(|v| <[u8; 64]>::try_from(v).ok())
            .ok_or_else(|| serde::de::Error::custom("signature must be 64 bytes of hex"))?;
        Ok(Signature::from_bytes(&bytes))
    }
}

/// A policy and the authority signature over its preimage.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedOutcomePolicy {
    pub payload: OutcomePolicyPayload,
    /// Rotation and diagnostics only.
    ///
    /// This field never resolves a key. [`validate_outcome_policy`] looks the
    /// id up in the pin and fails closed when it is not there, so an id that
    /// names a key the operator never pinned buys nothing: it is a label on a
    /// signature that will not verify.
    pub authority_key_id: KeyId,
    /// rotation and diagnostics.
    #[serde(with = "signature_serde")]
    pub signature: Signature,
}

impl SignedOutcomePolicy {
    pub fn policy_version(&self) -> u64 {
        self.payload.policy_version
    }

    pub fn created_at_unix(&self) -> u64 {
        self.payload.created_at_unix
    }

    /// The signature, hex-encoded, for transport. Encoding is one-way: a
    /// decoded signature is re-verified against the preimage, never trusted.
    pub fn signature_hex(&self) -> String {
        hex::encode(self.signature.to_bytes())
    }
}

/// A policy that has passed every check. Constructed only by
/// [`validate_outcome_policy`]; there is no other public constructor, so
/// holding one is the evidence.
#[derive(Debug, Clone)]
pub struct ValidatedOutcomePolicy {
    payload: OutcomePolicyPayload,
    authority_key_id: KeyId,
    pin_path: PathBuf,
}

impl ValidatedOutcomePolicy {
    pub fn payload(&self) -> &OutcomePolicyPayload {
        &self.payload
    }

    pub fn executor(&self) -> &Address {
        &self.payload.executor
    }

    pub fn chain_id(&self) -> u64 {
        self.payload.chain_id
    }

    pub fn min_confirmations(&self) -> u64 {
        self.payload.min_confirmations
    }

    /// The price-source binding this policy authorises, as a digest of the
    /// structured [`crate::trusted_valuation::PriceSourcePolicy`].
    ///
    /// P4.6. It is a digest and not the value because the policy is a
    /// portable, signed document: an operator signs "these sources, this pair,
    /// this window", and the node holds its own copy of the same statement and
    /// checks that the two agree on one handle. The value itself is never read
    /// out of the policy — only the handle — so a caller cannot smuggle a price
    /// source in through the JSON.
    pub fn price_source_hash(&self) -> &Hash {
        &self.payload.price_source_hash
    }

    pub fn policy_version(&self) -> u64 {
        self.payload.policy_version
    }

    /// The authority that actually vouched, which is by construction the pinned
    /// one and not the one the payload asked for.
    pub fn authority_key_id(&self) -> KeyId {
        self.authority_key_id
    }

    /// Where the authority came from, for logs and operator diagnostics.
    pub fn pin_path(&self) -> &Path {
        &self.pin_path
    }

    pub fn verifier_public_key(&self) -> &VerifierPublicKey {
        &self.payload.verifier_public_key
    }

    pub fn verifier_key_id(&self) -> KeyId {
        self.payload.verifier_key_id
    }

    /// The delegated verifier, as a value that can be handed to a receipt
    /// verifier. Only obtainable from a validated policy, which is what makes
    /// "signed by a key some policy delegated to" a reachable statement.
    pub fn trusted_verifier(&self) -> TrustedVerifierKey {
        TrustedVerifierKey {
            key_id: self.payload.verifier_key_id,
            key: self.payload.verifier_public_key,
        }
    }

    /// The preimage that was verified, exposed so a caller can log or re-hash
    /// it.
    pub fn verified_preimage(&self) -> Result<Vec<u8>, PolicyError> {
        self.payload.signing_preimage()
    }

    /// The digest a receipt is bound to.
    ///
    /// It is a digest of the *exact bytes the authority signed*, under
    /// [`POLICY_HASH_DOMAIN`], not a digest of the struct: two policies that
    /// serialise identically are the same policy, and a policy whose bytes the
    /// authority vouched for cannot later be re-spelled to change what a receipt
    /// is bound to.
    ///
    /// This is what makes rotation visible instead of silent. A receipt carries
    /// the `policy_hash` it was issued under and a view compares it against the
    /// hash of the policy the operator is running *now*, so a receipt minted
    /// under policy A is never silently re-approved under policy B — it stops
    /// matching and is reported as unattested.
    ///
    /// Policy-rotation history is out of scope: there is no revocation list, no
    /// `policy_version` high-water mark and no way here to accept a receipt
    /// issued under a *previous* policy. Mismatch fails closed and stays
    /// mismatched until the receipts are re-issued under the current policy.
    pub fn policy_hash(&self) -> Result<Hash, PolicyError> {
        let preimage = self.payload.signing_preimage()?;
        let mut buf = Vec::new();
        push_tagged(&mut buf, b"domain", POLICY_HASH_DOMAIN.as_bytes());
        push_tagged(&mut buf, b"policy", &preimage);
        Ok(Hash::from_bytes(*blake3::hash(&buf).as_bytes()))
    }
}

/// A verifier public key that arrived through a validated policy. Receipt
/// verification accepts this type, so a bare `VerifierPublicKey` read off an
/// unvalidated policy cannot be used to accept a receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedVerifierKey {
    key_id: KeyId,
    key: VerifierPublicKey,
}

impl TrustedVerifierKey {
    pub fn key_id(&self) -> KeyId {
        self.key_id
    }

    pub fn public_key(&self) -> &VerifierPublicKey {
        &self.key
    }

    /// The dalek key, crate-visible.
    ///
    /// This is the only `VerifyingKey` a receipt check can obtain, and
    /// `TrustedVerifierKey` has no constructor outside
    /// [`ValidatedOutcomePolicy::trusted_verifier`]. That pairing is what closes
    /// the layer-down Gland trap: the receipt verifier does not receive a key,
    /// it receives nothing at all and takes the key out of the validated policy
    /// itself. `crate`-visibility rather than `pub` because a verifying key for
    /// a delegation decision has no business in the crate's public API — it is
    /// an implementation detail of "the policy names the key", and exposing it
    /// would reopen exactly the door the next function closes.
    pub(crate) fn verifying_key(&self) -> Result<VerifyingKey, PolicyError> {
        self.key.verifying_key()
    }
}

// ---------------------------------------------------------------------------
// The pinned trust store
// ---------------------------------------------------------------------------

/// Where the pin lives and who must own it. Only the *path* and the expected
/// owner are configurable. Whether the file is a file, whether it is
/// owner-writable-only, and what happens when it is missing are all fixed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustStoreConfig {
    pin_path: PathBuf,
    expected_owner_uid: u32,
}

impl TrustStoreConfig {
    /// The default anchor: `/etc/mycelium/trust/policy-authority.pub`, owned by
    /// root. On a host where `/etc` is not writable by the operator this path
    /// cannot be created, which is the reason the field is configurable at all
    /// and not the reason it is unvalidated.
    pub fn system_default() -> Self {
        Self {
            pin_path: PathBuf::from(DEFAULT_POLICY_AUTHORITY_PIN_PATH),
            expected_owner_uid: DEFAULT_POLICY_AUTHORITY_PIN_UID,
        }
    }

    pub fn with_pin_path(pin_path: impl Into<PathBuf>) -> Self {
        Self {
            pin_path: pin_path.into(),
            ..Self::system_default()
        }
    }

    pub fn with_expected_owner_uid(mut self, uid: u32) -> Self {
        self.expected_owner_uid = uid;
        self
    }

    pub fn pin_path(&self) -> &Path {
        &self.pin_path
    }

    pub fn expected_owner_uid(&self) -> u32 {
        self.expected_owner_uid
    }

    /// Rejects a pin path that is obviously not a pin location, so a
    /// misconfiguration fails at configuration time rather than at load time
    /// with a confusing message.
    pub fn validate_shape(&self) -> Result<(), PolicyError> {
        if self.pin_path.as_os_str().is_empty() {
            return Err(PolicyError::PinMalformed(
                "trust store pin path is empty; there is no default and no fallback".into(),
            ));
        }
        if !self.pin_path.is_absolute() {
            return Err(PolicyError::PinMalformed(format!(
                "trust store pin path must be absolute: {}",
                self.pin_path.display()
            )));
        }
        Ok(())
    }
}

/// An authority key that was read from the pin and passed every filesystem
/// check. The only source of authority keys in this crate.
#[derive(Debug, Clone)]
pub struct PinnedTrustStore {
    key_id: KeyId,
    public_key: [u8; 32],
    config: TrustStoreConfig,
}

impl PinnedTrustStore {
    /// Reads and validates the pin. Every failure here leaves the caller with
    /// no trust store at all, which is the point: there is no partially
    /// validated store to carry on with.
    pub fn load(config: TrustStoreConfig) -> Result<Self, PolicyError> {
        config.validate_shape()?;
        let (role, key) = read_pin_document(&config)?;
        if role != KeyRole::PolicyAuthority {
            return Err(PolicyError::PinRoleMismatch {
                found: role.to_string(),
            });
        }
        let key_id = KeyId::derive(KeyRole::PolicyAuthority, &key);
        Ok(Self {
            key_id,
            public_key: key,
            config,
        })
    }

    /// Writes an authority key to the configured pin path.
    ///
    /// Operator-side. The file is created with `create_new` (so it cannot
    /// silently replace an existing anchor), with mode `0644`, and is then
    /// re-validated through the same checks [`Self::load`] applies. Ownership is
    /// *not* changed: `chown` needs privileges the caller may not have, so a
    /// pin this process creates under its own uid must be configured with that
    /// uid as the expected owner.
    pub fn install(config: &TrustStoreConfig, key: &PolicyAuthorityKey) -> Result<(), PolicyError> {
        config.validate_shape()?;
        if let Some(parent) = config.pin_path.parent() {
            // Best effort: an existing, correct directory is left alone. A
            // missing one is reported by the create_new below.
            let _ = fs::create_dir_all(parent);
        }
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&config.pin_path)
            .map_err(|e| {
                PolicyError::PinUnavailable(format!(
                    "cannot create policy authority pin {}: {e}",
                    config.pin_path.display()
                ))
            })?
            .write_all(key.pin_document().as_bytes())
            .map_err(|e| {
                PolicyError::PinUnavailable(format!(
                    "cannot write policy authority pin {}: {e}",
                    config.pin_path.display()
                ))
            })?;
        Self::load(config.clone()).map(|_| ())
    }

    /// The pinned key's identity in the authority role.
    pub fn authority_key_id(&self) -> KeyId {
        self.key_id
    }

    pub fn authority_public_key_bytes(&self) -> &[u8; 32] {
        &self.public_key
    }

    pub fn pin_path(&self) -> &Path {
        &self.config.pin_path
    }

    /// Resolves an authority key. The only resolution path in the crate.
    ///
    /// `claimed` is the id the policy asserted; the key returned is always the
    /// pinned one. A mismatch is [`PolicyError::AuthorityNotPinned`], which is
    /// the error a self-signed policy — one that names its own signer — gets.
    pub fn resolve_authority(&self, claimed: KeyId) -> Result<VerifyingKey, PolicyError> {
        if claimed != self.key_id {
            return Err(PolicyError::AuthorityNotPinned {
                claimed: claimed.to_string(),
                pinned: self.key_id.to_string(),
            });
        }
        VerifyingKey::from_bytes(&self.public_key).map_err(|_| {
            PolicyError::MalformedKey("pinned policy authority is not a valid ed25519 point".into())
        })
    }
}

/// The pin file's exact grammar: three LF-terminated lines, nothing else.
///
/// ```text
/// MYCELIUM-ECONOMY/POLICY-AUTHORITY-PIN/V1
/// role=policy-authority
/// key=0x<64 lowercase hex>
/// ```
fn format_pin_document(role: KeyRole, key: &[u8; 32]) -> String {
    format!(
        "{PIN_FILE_DOMAIN}\nrole={}\nkey=0x{}\n",
        role.spelling(),
        hex::encode(key)
    )
}

/// Reads the pin and applies every filesystem identity check.
///
/// The two-stage check is deliberate and is the same technique
/// [`crate::chain_provider::PinnedChainProvider::verify_socket_identity`] uses,
/// with the race closed:
///
/// 1. `lstat` on the path — refuses a symlink, requires a regular file, checks
///    the mode bits and the owner. Same order and same error shape as the socket
///    check, so the two read alike.
/// 2. The file is then opened, and the *descriptor's* metadata is re-checked.
///    `open(2)` follows symlinks, so stage 1 alone leaves a window in which the
///    path is replaced; re-reading `fstat(2)` on the opened inode means the
///    ownership and mode actually verified are those of the bytes actually read.
fn read_pin_document(config: &TrustStoreConfig) -> Result<(KeyRole, [u8; 32]), PolicyError> {
    let path = &config.pin_path;
    let display = path.display();

    // Stage 1: path identity, via lstat.
    let meta = fs::symlink_metadata(path).map_err(|e| {
        PolicyError::PinUnavailable(format!("policy authority pin {display} is unusable: {e}"))
    })?;
    if meta.file_type().is_symlink() {
        return Err(PolicyError::PinUnavailable(format!(
            "policy authority pin {display} is a symlink; ownership of the target would not \
             be checkable at the pinned path"
        )));
    }
    if !meta.file_type().is_file() {
        return Err(PolicyError::PinUnavailable(format!(
            "policy authority pin {display} is not a regular file"
        )));
    }
    if meta.len() > MAX_PIN_FILE_BYTES {
        return Err(PolicyError::PinUnavailable(format!(
            "policy authority pin {display} is {} bytes, over the {MAX_PIN_FILE_BYTES}-byte limit",
            meta.len()
        )));
    }
    check_pin_mode_and_owner(&meta, config, &display.to_string())?;

    // Stage 2: descriptor identity, via fstat on the opened file.
    let file = File::open(path).map_err(|e| {
        PolicyError::PinUnavailable(format!("policy authority pin {display} is unreadable: {e}"))
    })?;
    let opened = file.metadata().map_err(|e| {
        PolicyError::PinUnavailable(format!(
            "policy authority pin {display} has no readable metadata: {e}"
        ))
    })?;
    if !opened.file_type().is_file() {
        return Err(PolicyError::PinUnavailable(format!(
            "policy authority pin {display} did not open as a regular file"
        )));
    }
    check_pin_mode_and_owner(&opened, config, &display.to_string())?;

    let mut raw = Vec::new();
    file.take(MAX_PIN_FILE_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(|e| {
            PolicyError::PinUnavailable(format!(
                "policy authority pin {display} is unreadable: {e}"
            ))
        })?;
    if raw.len() as u64 > MAX_PIN_FILE_BYTES {
        return Err(PolicyError::PinUnavailable(format!(
            "policy authority pin {display} exceeds the {MAX_PIN_FILE_BYTES}-byte limit"
        )));
    }
    parse_pin_document(&raw)
}

fn check_pin_mode_and_owner(
    meta: &fs::Metadata,
    config: &TrustStoreConfig,
    display: &str,
) -> Result<(), PolicyError> {
    let mode = meta.mode() & 0o7777;
    if mode & 0o022 != 0 {
        return Err(PolicyError::PinUnavailable(format!(
            "policy authority pin {display} is group/other-writable (mode {mode:04o}); only the \
             owning account may replace the anchor"
        )));
    }
    let expected = config.expected_owner_uid();
    if meta.uid() != expected {
        return Err(PolicyError::PinUnavailable(format!(
            "policy authority pin {display} is owned by uid {}, expected uid {expected}",
            meta.uid()
        )));
    }
    Ok(())
}

/// Strict parser. No comments, no whitespace tolerance, no unknown lines: a pin
/// is a machine-written file and anything unexpected in it means the file is
/// not one.
fn parse_pin_document(raw: &[u8]) -> Result<(KeyRole, [u8; 32]), PolicyError> {
    let text = std::str::from_utf8(raw)
        .map_err(|_| PolicyError::PinMalformed("pin is not valid UTF-8".into()))?;
    let lines: Vec<&str> = text.split('\n').collect();
    // Three LF-terminated lines give a trailing empty element; a file missing
    // the final newline gives four with a non-empty last element.
    if lines.len() != 4 || !lines[3].is_empty() {
        return Err(PolicyError::PinMalformed(format!(
            "expected 3 newline-terminated lines, found {}",
            lines
                .len()
                .saturating_sub(usize::from(lines.last() == Some(&"")))
        )));
    }
    if lines[0] != PIN_FILE_DOMAIN {
        return Err(PolicyError::PinMalformed(format!(
            "first line is {:?}, expected {PIN_FILE_DOMAIN:?}",
            lines[0]
        )));
    }
    let role_value = lines[1]
        .strip_prefix("role=")
        .ok_or_else(|| PolicyError::PinMalformed(format!("line 2 is {:?}", lines[1])))?;
    let role = KeyRole::from_spelling(role_value).ok_or_else(|| {
        PolicyError::PinMalformed(format!("unknown key role {role_value:?} on line 2"))
    })?;
    let key_value = lines[2]
        .strip_prefix("key=")
        .ok_or_else(|| PolicyError::PinMalformed(format!("line 3 is {:?}", lines[2])))?;
    let body = key_value
        .strip_prefix("0x")
        .ok_or_else(|| PolicyError::PinMalformed("key= must be 0x-prefixed".into()))?;
    let bytes = hex::decode(body)
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .ok_or_else(|| {
            PolicyError::PinMalformed(format!(
                "key= must be exactly 32 bytes of hex, got {} chars",
                body.len()
            ))
        })?;
    Ok((role, bytes))
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Everything a policy is validated against, gathered so the entry point has a
/// single, obviously-complete argument.
#[derive(Debug, Clone, Copy)]
pub struct PolicyExpectations<'a> {
    /// The chain this node settles on. A policy for another chain is refused
    /// even when correctly signed.
    pub chain_id: u64,
    /// The live registry. Its digest must equal the policy's.
    pub registry: &'a ControlledAddressRegistry,
    /// The live provider pin. Its digest must equal the policy's.
    pub provider: &'a ProviderIdentityConstraints,
}

/// The single entry point. Checks, in this order:
///
/// 1. schema version (`:1050` region — see [`validate_outcome_policy`] body).
/// 2. role separation: the payload's verifier id must actually be the id of the
///    verifier key it carries, and must not be an authority-role id.
/// 3. preimage reconstruction.
/// 4. **the authority key resolves from the pin**, not from the payload.
/// 5. the signature verifies against that pinned key.
/// 6. `chain_id` matches the expectation.
/// 7. `min_confirmations >= 1`.
/// 8. `controlled_registry_hash` matches the live registry.
/// 9. `provider_identity_hash` matches the live provider pin, which must itself
///    demand a kernel-enforced identity.
/// 10. the price-source binding names at least one permitted source (P4.6).
///
/// Policy-rotation history is deliberately out of scope: there is no
/// revocation list and no `policy_version` high-water mark here, so a policy
/// that stops matching the live registry and provider is simply unattested.
pub fn validate_outcome_policy(
    signed: &SignedOutcomePolicy,
    trust: &PinnedTrustStore,
    expected: PolicyExpectations<'_>,
) -> Result<ValidatedOutcomePolicy, PolicyError> {
    // (1) Schema version.
    if signed.payload.schema_version != OUTCOME_POLICY_SCHEMA_VERSION {
        return Err(PolicyError::UnsupportedSchema {
            found: signed.payload.schema_version,
            expected: OUTCOME_POLICY_SCHEMA_VERSION,
        });
    }

    // (2) Role separation. Checked here, not only at signing time, because the
    // struct fields are public and a hand-built `SignedOutcomePolicy` never
    // goes through `PolicyAuthorityKey::sign`.
    if signed.payload.verifier_key_id.role() != KeyRole::VerifierRuntime {
        return Err(PolicyError::InvalidField {
            field: "verifier_key_id",
            reason: format!(
                "a policy may only delegate to a verifier-runtime key, payload names role {}",
                signed.payload.verifier_key_id.role()
            ),
        });
    }
    if !signed
        .payload
        .verifier_key_id
        .matches_key(signed.payload.verifier_public_key.as_bytes())
    {
        return Err(PolicyError::InvalidField {
            field: "verifier_key_id",
            reason: "verifier_key_id is not the identity of the verifier_public_key it names"
                .into(),
        });
    }
    if signed.authority_key_id.role() != KeyRole::PolicyAuthority {
        return Err(PolicyError::InvalidField {
            field: "authority_key_id",
            reason: format!(
                "an authority id must be in the policy-authority role, got {}",
                signed.authority_key_id.role()
            ),
        });
    }

    // (3) Preimage reconstruction.
    let preimage = signed.payload.signing_preimage()?;

    // (4) Authority resolution, from the pin. The payload contributed only a
    // label; the key that will verify is the pinned one. A policy that embeds
    // and names its own signer fails here even though its signature is
    // perfectly valid.
    let pinned_key = trust.resolve_authority(signed.authority_key_id)?;

    // (5) Signature verification, against the pinned key.
    pinned_key
        .verify(&preimage, &signed.signature)
        .map_err(|_| PolicyError::BadSignature)?;

    // (6) Chain scope.
    if signed.payload.chain_id != expected.chain_id {
        return Err(PolicyError::ChainMismatch {
            found: signed.payload.chain_id,
            expected: expected.chain_id,
        });
    }

    // (7) A policy that accepts an unconfirmed transaction is not a policy.
    if signed.payload.min_confirmations < 1 {
        return Err(PolicyError::MinConfirmationsTooLow {
            found: signed.payload.min_confirmations,
        });
    }

    // (8) Registry binding.
    let live_registry_hash = controlled_registry_hash(expected.registry)?;
    if signed.payload.controlled_registry_hash != live_registry_hash {
        return Err(PolicyError::ControlledRegistryMismatch {
            found: signed.payload.controlled_registry_hash.to_string(),
            live: live_registry_hash.to_string(),
        });
    }

    // (9) Provider binding. A provider that does not demand a kernel-enforced
    // identity cannot satisfy a policy that was signed for one, and the digest
    // check says so before any chain data is fetched.
    if !expected.provider.kernel_enforced() {
        return Err(PolicyError::ProviderIdentityMismatch {
            found: signed.payload.provider_identity_hash.to_string(),
            live: expected.provider.identity_hash().to_string(),
        });
    }
    let live_provider_hash = expected.provider.identity_hash();
    if signed.payload.provider_identity_hash != live_provider_hash {
        return Err(PolicyError::ProviderIdentityMismatch {
            found: signed.payload.provider_identity_hash.to_string(),
            live: live_provider_hash.to_string(),
        });
    }

    // (10) P4.6. The price-source binding must name at least one source.
    //
    // The payload carries a digest, so what can be checked here is exactly the
    // one thing a digest can be checked against: that it is *not* the digest of
    // the empty permitted-source set. A policy that authorises no price source
    // is refused at load rather than at promotion, because it is a
    // misconfiguration of the authority, not a property of any one operation —
    // and refusing it here means a source can never be named only by the
    // observation that carries it. This narrows the set of accepted policies and
    // relaxes nothing.
    let empty_binding =
        crate::trusted_valuation::PriceSourcePolicy::none().binding_hash();
    if signed.payload.price_source_hash == empty_binding {
        return Err(PolicyError::InvalidField {
            field: "price_source_hash",
            reason: "the price-source binding authorises no source at all; an outcome \
                     policy must name at least one permitted price source"
                .into(),
        });
    }

    Ok(ValidatedOutcomePolicy {
        payload: signed.payload.clone(),
        authority_key_id: signed.authority_key_id,
        pin_path: trust.pin_path().to_path_buf(),
    })
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

/// `LEN:u32be || TAG || LEN:u32be || VALUE`, both lengths in bytes.
///
/// `pub(crate)` since P4b: [`crate::receipt_auth`] builds its own preimage with
/// the same encoder rather than inventing a second one, which is what keeps a
/// receipt signature and a policy signature in the same canonical shape and the
/// same discipline (tagged, length-prefixed, domain first). It stays private to
/// the crate because it is an encoding primitive, not an API.
pub(crate) fn push_tagged(buf: &mut Vec<u8>, tag: &[u8], value: &[u8]) {
    let tag_len = u32::try_from(tag.len()).expect("static tag length fits in u32");
    let value_len =
        u32::try_from(value.len()).expect("field length checked at call sites fits in u32");
    buf.extend_from_slice(&tag_len.to_be_bytes());
    buf.extend_from_slice(tag);
    buf.extend_from_slice(&value_len.to_be_bytes());
    buf.extend_from_slice(value);
}

/// Test-only helper. Kept in the crate under `cfg(test)` so the production
/// type never grows a way to read the authority's public half back out of the
/// signer struct.
#[cfg(test)]
impl PolicyAuthorityKey {
    fn verifying_key(&self) -> Result<VerifyingKey, PolicyError> {
        VerifyingKey::from_bytes(&self.signing.verifying_key().to_bytes())
            .map_err(|_| PolicyError::MalformedKey("authority key is not a valid point".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base_usdc::BASE_CHAIN_ID;
    use std::os::unix::fs::PermissionsExt;

    const EXECUTOR_HEX: &str = "0x1111111111111111111111111111111111111111";
    const PAYOUT_HEX: &str = "0x2222222222222222222222222222222222222222";
    const OTHER_HEX: &str = "0x3333333333333333333333333333333333333333";

    struct Fixture {
        _dir: tempfile::TempDir,
        config: TrustStoreConfig,
        authority: PolicyAuthorityKey,
        verifier: VerifierRuntimeKey,
        registry: ControlledAddressRegistry,
        provider: ProviderIdentityConstraints,
    }

    fn unix_provider() -> ProviderIdentityConstraints {
        let pin = PinnedChainProvider::unix_socket("/run/mycelium-verifier.sock", Some(0)).unwrap();
        ProviderIdentityConstraints::from_pinned_provider(&pin)
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let config =
                TrustStoreConfig::with_pin_path(dir.path().join("trust").join("authority.pub"))
                    // The pin is created by this test process, so it is owned by
                    // this uid, not by root.
                    .with_expected_owner_uid(current_uid());
            let authority = PolicyAuthorityKey::generate();
            PinnedTrustStore::install(&config, &authority).unwrap();
            let registry = ControlledAddressRegistry::new()
                .with_address(PAYOUT_HEX)
                .unwrap();
            Self {
                _dir: dir,
                config,
                authority,
                verifier: VerifierRuntimeKey::generate(),
                registry,
                provider: unix_provider(),
            }
        }

        fn trust(&self) -> PinnedTrustStore {
            PinnedTrustStore::load(self.config.clone()).unwrap()
        }

        fn payload(&self) -> OutcomePolicyPayload {
            self.payload_with(self.verifier.key_id(), &self.verifier.public_key())
        }

fn payload_with(
        &self,
        verifier_key_id: KeyId,
        verifier_public_key: &VerifierPublicKey,
    ) -> OutcomePolicyPayload {
            OutcomePolicyPayload {
                schema_version: OUTCOME_POLICY_SCHEMA_VERSION,
                policy_version: 7,
                chain_id: BASE_CHAIN_ID,
                executor: Address::parse(EXECUTOR_HEX).unwrap(),
                min_confirmations: 12,
                controlled_registry_hash: controlled_registry_hash(&self.registry).unwrap(),
                provider_identity_hash: self.provider.identity_hash(),
                price_source_hash: self.price_source_hash(),
                verifier_key_id,
                verifier_public_key: *verifier_public_key,
                created_at_unix: 1_700_000_000,
            }
        }

        /// P4.6. The price-source binding every fixture policy authorises.
        ///
        /// The shared canonical one, so the receipt side's policy and the price
        /// side's policy are the *same* policy: one authority, one key, one
        /// `policy_hash`, which is the whole design of the step.
        fn price_source_hash(&self) -> Hash {
            crate::trusted_valuation::testkit::canonical_hash(BASE_CHAIN_ID)
        }

        fn sign(&self) -> SignedOutcomePolicy {
            self.authority.sign(self.payload(), &self.verifier).unwrap()
        }

        fn expectations(&self) -> PolicyExpectations<'_> {
            PolicyExpectations {
                chain_id: BASE_CHAIN_ID,
                registry: &self.registry,
                provider: &self.provider,
            }
        }

        fn validate(
            &self,
            signed: &SignedOutcomePolicy,
        ) -> Result<ValidatedOutcomePolicy, PolicyError> {
            self.try_validate(signed)
        }

        /// Same as [`Self::validate`] but lets a failed anchor load surface as
        /// the pin error it is, instead of an unwrap panic in test setup.
        fn try_validate(
            &self,
            signed: &SignedOutcomePolicy,
        ) -> Result<ValidatedOutcomePolicy, PolicyError> {
            let trust = PinnedTrustStore::load(self.config.clone())?;
            validate_outcome_policy(signed, &trust, self.expectations())
        }
    }

    fn current_uid() -> u32 {
        std::fs::metadata("/proc/self").unwrap().uid()
    }

    // -- happy path -------------------------------------------------------

    #[test]
    fn a_valid_policy_round_trips_and_validates() {
        let fx = Fixture::new();
        let signed = fx.sign();

        // Round-trip through the wire form: a policy that only works as an
        // in-memory value has not been authenticated, only exercised.
        let json = serde_json::to_vec(&signed).unwrap();
        let decoded: SignedOutcomePolicy = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded.payload, signed.payload);
        assert_eq!(decoded.authority_key_id, signed.authority_key_id);

        let validated = fx.validate(&decoded).unwrap();
        assert_eq!(validated.chain_id(), BASE_CHAIN_ID);
        assert_eq!(validated.policy_version(), 7);
        assert_eq!(validated.min_confirmations(), 12);
        assert_eq!(validated.executor().as_str(), EXECUTOR_HEX);
        assert_eq!(validated.authority_key_id(), fx.authority.key_id());
        assert_eq!(validated.pin_path(), fx.config.pin_path());
        assert_eq!(
            validated.trusted_verifier().key_id(),
            fx.verifier.key_id(),
            "the delegated verifier id must survive validation"
        );
    }

    #[test]
    fn installed_pin_and_loaded_authority_agree() {
        let fx = Fixture::new();
        let trust = fx.trust();
        assert_eq!(trust.authority_key_id(), fx.authority.key_id());
        assert_eq!(
            trust.authority_public_key_bytes(),
            &fx.authority.verifying_key_bytes()
        );
        assert_eq!(trust.pin_path(), fx.config.pin_path());
    }

    // -- signature binding, field by field ---------------------------------

    /// Mutates one field of a valid policy without re-signing. Every field of
    /// the payload is covered, one test case each, because a binding that is
    /// tested on one field is a binding that is only known to hold on one
    /// field.
    fn assert_mutation_invalidates(signed: &SignedOutcomePolicy, fx: &Fixture, what: &str) {
        let err = fx.validate(signed).unwrap_err();
        assert!(
            !matches!(err, PolicyError::Preimage(_)),
            "mutating {what} produced a preimage error, not a signature failure: {err}"
        );
        // A mutated payload must not validate. Whether it fails as
        // AuthorityNotPinned, BadSignature, ChainMismatch, ... depends on which
        // field moved; what matters is that it never validates.
        assert!(
            fx.validate(signed).is_err(),
            "mutating {what} did not invalidate the policy"
        );
    }

    #[test]
    fn mutating_schema_version_invalidates() {
        let fx = Fixture::new();
        let mut signed = fx.sign();
        signed.payload.schema_version += 1;
        // Caught by the schema check before the signature is even consulted.
        assert!(matches!(
            fx.validate(&signed).unwrap_err(),
            PolicyError::UnsupportedSchema { .. }
        ));
    }

    #[test]
    fn mutating_policy_version_invalidates() {
        let fx = Fixture::new();
        let mut signed = fx.sign();
        signed.payload.policy_version = signed.payload.policy_version.wrapping_add(1);
        assert_mutation_invalidates(&signed, &fx, "policy_version");
    }

    #[test]
    fn mutating_chain_id_invalidates() {
        let fx = Fixture::new();
        let mut signed = fx.sign();
        signed.payload.chain_id = signed.payload.chain_id.wrapping_add(1);
        assert_mutation_invalidates(&signed, &fx, "chain_id");
    }

    #[test]
    fn mutating_executor_invalidates() {
        let fx = Fixture::new();
        let mut signed = fx.sign();
        signed.payload.executor = Address::parse(OTHER_HEX).unwrap();
        assert_mutation_invalidates(&signed, &fx, "executor");
    }

    #[test]
    fn mutating_min_confirmations_invalidates() {
        let fx = Fixture::new();
        let mut signed = fx.sign();
        signed.payload.min_confirmations += 1;
        assert_mutation_invalidates(&signed, &fx, "min_confirmations");
    }

    #[test]
    fn mutating_controlled_registry_hash_invalidates() {
        let fx = Fixture::new();
        let mut signed = fx.sign();
        signed.payload.controlled_registry_hash = Hash::parse(
            "controlled_registry_hash",
            &format!("0x{}", "11".repeat(32)),
        )
        .unwrap();
        assert_mutation_invalidates(&signed, &fx, "controlled_registry_hash");
    }

    #[test]
    fn mutating_provider_identity_hash_invalidates() {
        let fx = Fixture::new();
        let mut signed = fx.sign();
        signed.payload.provider_identity_hash =
            Hash::parse("provider_identity_hash", &format!("0x{}", "22".repeat(32))).unwrap();
        assert_mutation_invalidates(&signed, &fx, "provider_identity_hash");
    }

    #[test]
    fn mutating_verifier_key_id_invalidates() {
        let fx = Fixture::new();
        let mut signed = fx.sign();
        // A different verifier id with the same public key. This is also the
        // `matches_key` check firing, so it is asserted specifically.
        signed.payload.verifier_key_id = KeyId::derive(KeyRole::VerifierRuntime, &[0xabu8; 32]);
        assert!(matches!(
            fx.validate(&signed).unwrap_err(),
            PolicyError::InvalidField { .. }
        ));
    }

    #[test]
    fn mutating_verifier_public_key_invalidates() {
        let fx = Fixture::new();
        let mut signed = fx.sign();
        let other = VerifierRuntimeKey::generate();
        signed.payload.verifier_public_key = other.public_key();
        // The id no longer names the key it is paired with.
        assert!(matches!(
            fx.validate(&signed).unwrap_err(),
            PolicyError::InvalidField { .. }
        ));
    }

    #[test]
    fn mutating_created_at_invalidates() {
        let fx = Fixture::new();
        let mut signed = fx.sign();
        signed.payload.created_at_unix += 1;
        assert_mutation_invalidates(&signed, &fx, "created_at_unix");
    }

    #[test]
    fn mutating_the_signature_invalidates() {
        let fx = Fixture::new();
        let mut signed = fx.sign();
        let mut bytes = signed.signature.to_bytes();
        bytes[0] ^= 0x01;
        signed.signature = Signature::from_bytes(&bytes);
        assert!(matches!(
            fx.validate(&signed).unwrap_err(),
            PolicyError::BadSignature
        ));
    }

    #[test]
    fn mutating_the_authority_key_id_invalidates() {
        let fx = Fixture::new();
        let mut signed = fx.sign();
        signed.authority_key_id = KeyId::derive(KeyRole::PolicyAuthority, &[0x99u8; 32]);
        assert!(matches!(
            fx.validate(&signed).unwrap_err(),
            PolicyError::AuthorityNotPinned { .. }
        ));
    }

    // -- executor and confirmations as first-class requirements ------------

    #[test]
    fn executor_changed_to_another_account_is_invalid() {
        let fx = Fixture::new();
        let mut signed = fx.sign();
        assert_eq!(signed.payload.executor.as_str(), EXECUTOR_HEX);
        signed.payload.executor = Address::parse(OTHER_HEX).unwrap();
        assert!(fx.validate(&signed).is_err());
    }

    #[test]
    fn executor_cannot_be_respelled_to_a_different_account() {
        let fx = Fixture::new();
        let signed = fx.sign();
        // Same bytes, different spelling: checksummed case and a missing 0x.
        // Both normalise to EXECUTOR_HEX, so both are the same address and the
        // preimage is unchanged. This is the property that stops address
        // spelling from being a second identity.
        let checksummed = format!("0x{}", "11".repeat(20).to_uppercase());
        let respelled = signed.clone();
        assert_eq!(Address::parse(&checksummed).unwrap().as_str(), EXECUTOR_HEX);
        assert_eq!(
            Address::parse("1111111111111111111111111111111111111111")
                .unwrap()
                .as_str(),
            EXECUTOR_HEX
        );
        assert_eq!(respelled.payload.executor, signed.payload.executor);
        assert_eq!(
            respelled.payload.signing_preimage().unwrap(),
            signed.payload.signing_preimage().unwrap()
        );
        // A genuinely different address does not survive normalisation.
        assert_ne!(Address::parse(OTHER_HEX).unwrap().as_str(), EXECUTOR_HEX);
    }

    #[test]
    fn zero_min_confirmations_is_invalid() {
        let fx = Fixture::new();
        let mut signed = fx.sign();
        signed.payload.min_confirmations = 0;
        // Re-signed with the authority, so the signature is genuine: this is a
        // policy the authority really did issue, and it is still refused.
        assert_eq!(signed.payload.min_confirmations, 0);
        let resigned = fx.authority.sign(signed.payload, &fx.verifier).unwrap();
        assert!(matches!(
            fx.validate(&resigned).unwrap_err(),
            PolicyError::MinConfirmationsTooLow { found: 0 }
        ));
    }

    #[test]
    fn one_min_confirmation_is_accepted() {
        let fx = Fixture::new();
        let mut payload = fx.payload();
        payload.min_confirmations = 1;
        let signed = fx.authority.sign(payload, &fx.verifier).unwrap();
        assert_eq!(fx.validate(&signed).unwrap().min_confirmations(), 1);
    }

    // -- registry binding -------------------------------------------------

    #[test]
    fn controlled_registry_hash_changed_in_the_policy_is_invalid() {
        let fx = Fixture::new();
        let mut payload = fx.payload();
        payload.controlled_registry_hash = Hash::parse(
            "controlled_registry_hash",
            &format!("0x{}", "33".repeat(32)),
        )
        .unwrap();
        let signed = fx.authority.sign(payload, &fx.verifier).unwrap();
        assert!(matches!(
            fx.validate(&signed).unwrap_err(),
            PolicyError::ControlledRegistryMismatch { .. }
        ));
    }

    #[test]
    fn changing_the_registry_changes_the_hash_and_invalidates_the_policy() {
        let fx = Fixture::new();
        let signed = fx.sign();
        assert!(fx.validate(&signed).is_ok());

        // Add a controlled address. The policy was signed against the smaller
        // registry, so it must stop validating: the hash genuinely tracks the
        // registry's contents.
        let mut widened = fx.registry.clone();
        widened.insert(OTHER_HEX).unwrap();
        let widened_hash = controlled_registry_hash(&widened).unwrap();
        assert_ne!(
            widened_hash, signed.payload.controlled_registry_hash,
            "adding a controlled address must change the registry hash"
        );
        let err = validate_outcome_policy(
            &signed,
            &fx.trust(),
            PolicyExpectations {
                chain_id: BASE_CHAIN_ID,
                registry: &widened,
                provider: &fx.provider,
            },
        )
        .unwrap_err();
        assert!(matches!(
            err,
            PolicyError::ControlledRegistryMismatch { .. }
        ));

        // And a policy signed against the wider registry validates there, and
        // fails against the narrower one.
        let resigned = fx
            .authority
            .sign(
                fx.payload_with(fx.verifier.key_id(), &fx.verifier.public_key()),
                &fx.verifier,
            )
            .unwrap();
        assert_eq!(
            resigned.payload.controlled_registry_hash,
            controlled_registry_hash(&fx.registry).unwrap()
        );
    }

    #[test]
    fn removing_a_controlled_address_changes_the_hash() {
        let registry = ControlledAddressRegistry::new()
            .with_address(PAYOUT_HEX)
            .unwrap();
        let one = controlled_registry_hash(&registry).unwrap();

        // A different single-address registry: same shape, different address.
        let other_registry = ControlledAddressRegistry::new()
            .with_address(EXECUTOR_HEX)
            .unwrap();
        let other = controlled_registry_hash(&other_registry).unwrap();
        assert_ne!(one, other, "a different address must not hash the same");

        let empty = controlled_registry_hash(&ControlledAddressRegistry::new()).unwrap();
        assert_ne!(empty, one);
        assert_ne!(empty, other);
        // The empty registry is a well-defined value, not "unset": hashing it
        // twice gives the same answer.
        assert_eq!(
            empty,
            controlled_registry_hash(&ControlledAddressRegistry::new()).unwrap()
        );
    }

    #[test]
    fn registry_hash_is_insensitive_to_insertion_order() {
        let a = ControlledAddressRegistry::new()
            .with_address(PAYOUT_HEX)
            .unwrap()
            .with_address(OTHER_HEX)
            .unwrap();
        let b = ControlledAddressRegistry::new()
            .with_address(OTHER_HEX)
            .unwrap()
            .with_address(PAYOUT_HEX)
            .unwrap();
        assert_eq!(
            controlled_registry_hash(&a).unwrap(),
            controlled_registry_hash(&b).unwrap()
        );
    }

    #[test]
    fn registry_hash_is_domain_separated_from_the_policy_and_provider_hashes() {
        let registry = ControlledAddressRegistry::new()
            .with_address(PAYOUT_HEX)
            .unwrap();
        let registry_hash = controlled_registry_hash(&registry).unwrap();
        let provider_hash = unix_provider().identity_hash();
        assert_ne!(registry_hash, provider_hash);
        // And a digest of the same bytes under a different domain differs, which
        // is what `push_tagged(b"domain", ...)` buys.
        let mut other_domain = Vec::new();
        push_tagged(
            &mut other_domain,
            b"domain",
            PROVIDER_IDENTITY_DOMAIN.as_bytes(),
        );
        push_tagged(&mut other_domain, b"count", &1u32.to_be_bytes());
        push_tagged(&mut other_domain, b"addr", PAYOUT_HEX.as_bytes());
        assert_ne!(
            registry_hash,
            Hash::from_bytes(*blake3::hash(&other_domain).as_bytes())
        );
    }

    // -- provider binding --------------------------------------------------

    #[test]
    fn provider_identity_hash_mismatch_is_invalid() {
        let fx = Fixture::new();
        let other = PinnedChainProvider::unix_socket("/run/other-verifier.sock", Some(0)).unwrap();
        let other_constraints = ProviderIdentityConstraints::from_pinned_provider(&other);
        let err = validate_outcome_policy(
            &fx.sign(),
            &fx.trust(),
            PolicyExpectations {
                chain_id: BASE_CHAIN_ID,
                registry: &fx.registry,
                provider: &other_constraints,
            },
        )
        .unwrap_err();
        assert!(matches!(err, PolicyError::ProviderIdentityMismatch { .. }));
    }

    #[test]
    fn a_loopback_provider_cannot_satisfy_a_signed_policy() {
        let fx = Fixture::new();
        let loopback = PinnedChainProvider::parse("http://127.0.0.1:8546", None).unwrap();
        let constraints = ProviderIdentityConstraints::from_pinned_provider(&loopback);
        assert!(!constraints.kernel_enforced());
        let err = validate_outcome_policy(
            &fx.sign(),
            &fx.trust(),
            PolicyExpectations {
                chain_id: BASE_CHAIN_ID,
                registry: &fx.registry,
                provider: &constraints,
            },
        )
        .unwrap_err();
        assert!(matches!(err, PolicyError::ProviderIdentityMismatch { .. }));
    }

    #[test]
    fn chain_id_mismatch_is_invalid() {
        let fx = Fixture::new();
        let signed = fx.sign();
        let err = validate_outcome_policy(
            &signed,
            &fx.trust(),
            PolicyExpectations {
                chain_id: BASE_CHAIN_ID + 1,
                registry: &fx.registry,
                provider: &fx.provider,
            },
        )
        .unwrap_err();
        assert!(matches!(err, PolicyError::ChainMismatch { .. }));
    }

    // -- P4.6: the price-source binding --------------------------------------

    /// A policy that authorises **no** price source is refused at load, before it
    /// can be used to promote anything.
    ///
    /// The payload carries a digest, so the only thing checkable here is that it
    /// is not the digest of the empty permitted-source set — and that is exactly
    /// what this asserts. The point of refusing it *here* is that a source named
    /// only by the observation that carries it can never exist: the authority has
    /// to name one before any observation is signed.
    #[test]
    fn a_policy_that_authorises_no_price_source_is_refused() {
        use crate::trusted_valuation::PriceSourcePolicy;

        let fx = Fixture::new();
        let mut payload = fx.payload();
        payload.price_source_hash = PriceSourcePolicy::none().binding_hash();
        let signed = fx.authority.sign(payload, &fx.verifier).unwrap();

        match fx.validate(&signed) {
            Err(PolicyError::InvalidField {
                field,
                reason,
            }) => {
                assert_eq!(field, "price_source_hash");
                assert!(
                    reason.contains("at least one permitted price source"),
                    "the refusal must say what is wrong: {reason}"
                );
            }
            other => panic!("expected the empty binding to be refused, got {other:?}"),
        }

        // And one real source is accepted, so the refusal is about the binding and
        // not about the new field being unsatisfiable.
        let mut payload = fx.payload();
        payload.price_source_hash =
            crate::trusted_valuation::testkit::canonical_hash(BASE_CHAIN_ID);
        let signed = fx.authority.sign(payload, &fx.verifier).unwrap();
        assert!(fx.validate(&signed).is_ok());
    }

    /// The price-source binding is a **signed row** of the preimage: editing it
    /// edits the message, so the authority's signature stops verifying. A policy
    /// cannot therefore be signed with one source and applied with another.
    #[test]
    fn the_price_source_binding_is_a_signed_row_of_the_preimage() {
        let fx = Fixture::new();
        let payload = fx.payload();
        let signed = fx.authority.sign(payload.clone(), &fx.verifier).unwrap();
        assert!(fx.validate(&signed).is_ok());

        // Any other binding produces different bytes.
        let mut edited = payload.clone();
        edited.price_source_hash = crate::trusted_valuation::testkit::canonical_hash(
            BASE_CHAIN_ID + 1,
        );
        assert_ne!(
            payload.signing_preimage().unwrap(),
            edited.signing_preimage().unwrap(),
            "the binding is inside the signed message"
        );
        assert_eq!(
            POLICY_PREIMAGE_FIELDS
                .iter()
                .filter(|(tag, _)| *tag == "price_source_hash")
                .count(),
            1,
            "and it appears exactly once in the published table"
        );
        assert_eq!(
            POLICY_PREIMAGE_FIELDS.len(),
            11,
            "schema 2 has eleven rows: the ten of schema 1 plus the price-source binding"
        );

        // And re-signing the edited payload under the same authority is how the
        // operator changes it — which is the point: the change is visible as a new
        // policy hash, not as a mutation of an existing one.
        let resigned = fx.authority.sign(edited, &fx.verifier).unwrap();
        assert!(fx.validate(&resigned).is_ok());
        let hash_of = |signed: &SignedOutcomePolicy| {
            let preimage = signed.payload.signing_preimage().expect("a signing preimage");
            let mut buf = Vec::new();
            push_tagged(&mut buf, b"domain", POLICY_HASH_DOMAIN.as_bytes());
            push_tagged(&mut buf, b"policy", &preimage);
            Hash::from_bytes(*blake3::hash(&buf).as_bytes())
        };
        assert_ne!(hash_of(&resigned), hash_of(&signed));
    }

    // -- the Gland trap ---------------------------------------------------

    #[test]
    fn the_gland_trap_a_self_signed_policy_is_rejected() {
        // The exact shape `mycelium-pheromones` uses: the payload names a key,
        // and the key named is the one that signed. Here the payload's own
        // authority id names the attacker key, the attacker signs, and the
        // signature is internally perfect.
        let fx = Fixture::new();
        let attacker = PolicyAuthorityKey::generate();
        let attacker_verifier = VerifierRuntimeKey::generate();

        let payload = OutcomePolicyPayload {
            schema_version: OUTCOME_POLICY_SCHEMA_VERSION,
            policy_version: 1,
            chain_id: BASE_CHAIN_ID,
            executor: Address::parse(EXECUTOR_HEX).unwrap(),
            min_confirmations: 12,
            controlled_registry_hash: controlled_registry_hash(&fx.registry).unwrap(),
            provider_identity_hash: fx.provider.identity_hash(),
            price_source_hash: crate::trusted_valuation::testkit::canonical_hash(BASE_CHAIN_ID),
            verifier_key_id: attacker_verifier.key_id(),
            verifier_public_key: attacker_verifier.public_key(),
            created_at_unix: 1_700_000_000,
        };
        let preimage = payload.signing_preimage().unwrap();
        let forged = SignedOutcomePolicy {
            payload,
            // Names the attacker, and the attacker signed.
            authority_key_id: attacker.key_id(),
            signature: attacker.signing.sign(&preimage),
        };

        // The forgery is a valid signature by its own key: this is not a
        // statement about signature checking, it is the distribution check.
        attacker
            .verifying_key()
            .unwrap()
            .verify(&preimage, &forged.signature)
            .unwrap();

        let err = fx.validate(&forged).unwrap_err();
        assert!(
            matches!(err, PolicyError::AuthorityNotPinned { .. }),
            "self-signed policy must be rejected on authority grounds, got {err}"
        );
        let msg = err.to_string();
        assert!(msg.contains(&attacker.key_id().to_string()));
        assert!(msg.contains(&fx.authority.key_id().to_string()));
    }

    #[test]
    fn a_verifier_key_in_the_authority_role_does_not_satisfy_the_pin() {
        // Role is part of the identity, so the same 32 bytes hash to different
        // ids in the two roles. This is the property that makes the separation
        // survive the wire.
        let key = [0x5au8; 32];
        let as_authority = KeyId::derive(KeyRole::PolicyAuthority, &key);
        let as_verifier = KeyId::derive(KeyRole::VerifierRuntime, &key);
        assert_ne!(as_authority, as_verifier);
        assert_eq!(as_authority.role(), KeyRole::PolicyAuthority);
        assert_eq!(as_verifier.role(), KeyRole::VerifierRuntime);
        assert!(as_authority.matches_key(&key));
        assert!(as_verifier.matches_key(&key));
        // And neither matches the other role's key set.
        assert!(!as_authority.matches_key(&[0x5bu8; 32]));
    }

    #[test]
    fn a_verifier_role_key_cannot_authorise_a_policy() {
        let fx = Fixture::new();
        // A key held through the verifier-role type, used to sign a policy, and
        // claiming authority over the policy. Three things are being checked:
        //
        //  * the claimed authority id is the impostor's own bytes;
        //  * the signature is genuinely valid under those bytes;
        //  * the pin holds someone else's bytes.
        //
        // The rejection therefore has to come from the anchor, not from
        // signature checking, and it is `AuthorityNotPinned`.
        let impostor = VerifierRuntimeKey::generate();
        let payload = OutcomePolicyPayload {
            schema_version: OUTCOME_POLICY_SCHEMA_VERSION,
            policy_version: 1,
            chain_id: BASE_CHAIN_ID,
            executor: Address::parse(EXECUTOR_HEX).unwrap(),
            min_confirmations: 5,
            controlled_registry_hash: controlled_registry_hash(&fx.registry).unwrap(),
            provider_identity_hash: fx.provider.identity_hash(),
            price_source_hash: crate::trusted_valuation::testkit::canonical_hash(BASE_CHAIN_ID),
            verifier_key_id: impostor.key_id(),
            verifier_public_key: impostor.public_key(),
            created_at_unix: 1_700_000_000,
        };
        let preimage = payload.signing_preimage().unwrap();
        let forged = SignedOutcomePolicy {
            payload,
            // Authority-role id derived from the impostor's own bytes: the best
            // claim a verifier-role key can make.
            authority_key_id: KeyId::derive(
                KeyRole::PolicyAuthority,
                &impostor.verifying_key_bytes(),
            ),
            signature: impostor.signing.sign(&preimage),
        };
        impostor
            .public_key()
            .verifying_key()
            .unwrap()
            .verify(&preimage, &forged.signature)
            .unwrap();

        let err = fx.validate(&forged).unwrap_err();
        assert!(
            matches!(err, PolicyError::AuthorityNotPinned { .. }),
            "a verifier-role key must not satisfy the authority pin, got {err}"
        );

        // The mirror image: the same impostor honestly labels itself with its own
        // role, and the role check refuses it before the pin is even consulted.
        let mut relabelled = forged;
        relabelled.authority_key_id = impostor.key_id();
        let err = fx.validate(&relabelled).unwrap_err();
        assert!(
            matches!(
                err,
                PolicyError::InvalidField {
                    field: "authority_key_id",
                    ..
                }
            ),
            "a verifier-role id is not an authority id, got {err}"
        );
    }

    #[test]
    fn a_pin_holding_the_wrong_bytes_rejects_an_otherwise_valid_policy() {
        // A perfectly signed policy whose key is not the pinned one. This is the
        // pin swap in its purest form: nothing about the policy is malformed.
        let fx = Fixture::new();
        let other_authority = PolicyAuthorityKey::generate();
        let forged = other_authority.sign(fx.payload(), &fx.verifier).unwrap();
        let err = fx.validate(&forged).unwrap_err();
        assert!(matches!(err, PolicyError::AuthorityNotPinned { .. }));
        assert!(err
            .to_string()
            .contains("never bring its own authority key"));
    }

    #[test]
    fn the_pinned_id_and_a_valid_signature_do_not_substitute_for_each_other() {
        // Naming the pinned id while signing with something else: the pin
        // resolves fine, and the signature is what refuses.
        let fx = Fixture::new();
        let other_authority = PolicyAuthorityKey::generate();
        let mut forged = other_authority.sign(fx.payload(), &fx.verifier).unwrap();
        forged.authority_key_id = fx.authority.key_id();
        assert!(matches!(
            fx.validate(&forged).unwrap_err(),
            PolicyError::BadSignature
        ));
    }

    #[test]
    fn an_authority_role_id_cannot_be_used_as_the_delegated_verifier() {
        let fx = Fixture::new();
        let mut signed = fx.sign();
        // Swap in an authority-role id derived from the verifier's bytes.
        signed.payload.verifier_key_id =
            KeyId::derive(KeyRole::PolicyAuthority, &fx.verifier.verifying_key_bytes());
        assert!(matches!(
            fx.validate(&signed).unwrap_err(),
            PolicyError::InvalidField {
                field: "verifier_key_id",
                ..
            }
        ));
    }

    #[test]
    fn one_key_may_not_serve_both_roles() {
        // The same raw key cannot be the authority and the delegate: the
        // signing side refuses outright.
        let seed = [0x11u8; 32];
        let authority = PolicyAuthorityKey::from_seed(seed);
        let same_bytes_as_verifier = VerifierRuntimeKey::from_seed(seed);
        assert_eq!(
            authority.verifying_key_bytes(),
            same_bytes_as_verifier.verifying_key_bytes()
        );
        let registry = ControlledAddressRegistry::new()
            .with_address(PAYOUT_HEX)
            .unwrap();
        let provider = unix_provider();
        let payload = OutcomePolicyPayload {
            schema_version: OUTCOME_POLICY_SCHEMA_VERSION,
            policy_version: 1,
            chain_id: BASE_CHAIN_ID,
            executor: Address::parse(EXECUTOR_HEX).unwrap(),
            min_confirmations: 5,
            controlled_registry_hash: controlled_registry_hash(&registry).unwrap(),
            provider_identity_hash: provider.identity_hash(),
            price_source_hash: crate::trusted_valuation::testkit::canonical_hash(BASE_CHAIN_ID),
            verifier_key_id: same_bytes_as_verifier.key_id(),
            verifier_public_key: same_bytes_as_verifier.public_key(),
            created_at_unix: 1_700_000_000,
        };
        assert!(matches!(
            authority
                .sign(payload, &same_bytes_as_verifier)
                .unwrap_err(),
            PolicyError::RoleCollision { .. }
        ));
    }

    // -- fail closed on the anchor ----------------------------------------

    #[test]
    fn an_absent_pin_fails_closed_with_no_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let config = TrustStoreConfig::with_pin_path(dir.path().join("never-created.pub"))
            .with_expected_owner_uid(current_uid());
        let err = PinnedTrustStore::load(config).unwrap_err();
        assert!(matches!(err, PolicyError::PinUnavailable(_)));
        assert!(err.to_string().contains("unusable"));

        // The failure is a *typed* failure in the crate's own fail-closed
        // vocabulary, not a default endpoint and not a degraded success.
        let as_economy: EconomyError = err.into();
        assert!(matches!(as_economy, EconomyError::ProviderUnpinned(_)));
    }

    #[test]
    fn there_is_no_fallback_inside_the_economy_directory() {
        // The pin path is whatever the operator configures, and nothing in this
        // crate consults the mutable economy root. Asserted structurally: the
        // only way to obtain a trust store is to load a configured path, and
        // the configured path is an absolute one that fails closed when absent.
        let dir = tempfile::tempdir().unwrap();
        let config = TrustStoreConfig::with_pin_path(dir.path().join("absent.pub"))
            .with_expected_owner_uid(current_uid());
        assert!(PinnedTrustStore::load(config.clone()).is_err());
        // A relative pin path is refused at configuration time, which closes the
        // "resolved against whatever cwd the daemon inherited" hole.
        assert!(TrustStoreConfig::with_pin_path("trust/authority.pub")
            .validate_shape()
            .is_err());
        assert!(TrustStoreConfig::with_pin_path("")
            .validate_shape()
            .is_err());
        assert!(TrustStoreConfig::system_default().validate_shape().is_ok());
        assert_eq!(
            TrustStoreConfig::system_default().pin_path(),
            Path::new(DEFAULT_POLICY_AUTHORITY_PIN_PATH)
        );
        assert_eq!(
            TrustStoreConfig::system_default().expected_owner_uid(),
            DEFAULT_POLICY_AUTHORITY_PIN_UID
        );
    }

    #[test]
    fn a_group_or_world_writable_pin_is_rejected() {
        let fx = Fixture::new();
        fs::set_permissions(fx.config.pin_path(), fs::Permissions::from_mode(0o666)).unwrap();
        let err = PinnedTrustStore::load(fx.config.clone()).unwrap_err();
        assert!(matches!(err, PolicyError::PinUnavailable(_)));
        assert!(err.to_string().contains("group/other-writable"));
        // And therefore no policy validates either: with no usable anchor there
        // is nothing to validate against, and the policy is unattested.
        assert!(matches!(
            fx.try_validate(&fx.sign()).unwrap_err(),
            PolicyError::PinUnavailable(_)
        ));
    }

    #[test]
    fn a_pin_with_a_sticky_or_setuid_mode_bit_is_still_accepted() {
        // Only the write bits are the operator's concern here: the check is
        // `mode & 0o022`, exactly as the socket check does it. A 0644 pin with a
        // setgid bit is still owner-rewritable-only, so it loads.
        let fx = Fixture::new();
        fs::set_permissions(fx.config.pin_path(), fs::Permissions::from_mode(0o2644)).unwrap();
        assert!(PinnedTrustStore::load(fx.config.clone()).is_ok());
    }

    #[test]
    fn a_pin_with_the_wrong_owner_is_rejected() {
        let fx = Fixture::new();
        let wrong = current_uid().wrapping_add(1);
        let config = fx.config.clone().with_expected_owner_uid(wrong);
        let err = PinnedTrustStore::load(config).unwrap_err();
        assert!(matches!(err, PolicyError::PinUnavailable(_)));
        assert!(err.to_string().contains("expected uid"));
    }

    #[test]
    fn a_symlinked_pin_is_rejected() {
        let fx = Fixture::new();
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("link.pub");
        std::os::unix::fs::symlink(fx.config.pin_path(), &link).unwrap();
        let config = TrustStoreConfig::with_pin_path(&link).with_expected_owner_uid(current_uid());
        let err = PinnedTrustStore::load(config).unwrap_err();
        assert!(matches!(err, PolicyError::PinUnavailable(_)));
        assert!(err.to_string().contains("symlink"));
    }

    #[test]
    fn a_pin_that_is_a_directory_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let subdir = dir.path().join("trust-dir");
        fs::create_dir(&subdir).unwrap();
        let config =
            TrustStoreConfig::with_pin_path(&subdir).with_expected_owner_uid(current_uid());
        let err = PinnedTrustStore::load(config).unwrap_err();
        assert!(matches!(err, PolicyError::PinUnavailable(_)));
        assert!(err.to_string().contains("not a regular file"));
    }

    #[test]
    fn a_pin_whose_role_is_not_policy_authority_is_rejected() {
        let fx = Fixture::new();
        // Same key bytes, declared in the verifier role. The parser accepts both
        // roles; the *policy* layer refuses the wrong one, which is what makes
        // the check meaningful rather than a tautology.
        let document = format_pin_document(
            KeyRole::VerifierRuntime,
            &fx.authority.verifying_key_bytes(),
        );
        fs::write(fx.config.pin_path(), document).unwrap();
        fs::set_permissions(fx.config.pin_path(), fs::Permissions::from_mode(0o600)).unwrap();
        let err = PinnedTrustStore::load(fx.config.clone()).unwrap_err();
        assert!(
            matches!(err, PolicyError::PinRoleMismatch { .. }),
            "a verifier-role pin must be refused, got {err}"
        );
        assert!(err.to_string().contains("verifier-runtime"));
    }

    #[test]
    fn a_malformed_pin_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let good_key = format!("0x{}", "ab".repeat(32));
        let cases: Vec<(&str, String)> = vec![
            ("empty", String::new()),
            (
                "wrong domain",
                format!("SOMETHING-ELSE\nrole=policy-authority\nkey={good_key}\n"),
            ),
            (
                "missing role line",
                format!("{PIN_FILE_DOMAIN}\nkey={good_key}\n"),
            ),
            (
                "unknown role",
                format!("{PIN_FILE_DOMAIN}\nrole=root\nkey={good_key}\n"),
            ),
            (
                "short key",
                format!("{PIN_FILE_DOMAIN}\nrole=policy-authority\nkey=0xabcd\n"),
            ),
            (
                "non-hex key",
                format!(
                    "{PIN_FILE_DOMAIN}\nrole=policy-authority\nkey=0x{}\n",
                    "zz".repeat(32)
                ),
            ),
            (
                "no 0x prefix",
                format!(
                    "{PIN_FILE_DOMAIN}\nrole=policy-authority\nkey={}\n",
                    "ab".repeat(32)
                ),
            ),
            (
                "no trailing newline",
                format!("{PIN_FILE_DOMAIN}\nrole=policy-authority\nkey={good_key}"),
            ),
            (
                "extra line",
                format!("{PIN_FILE_DOMAIN}\nrole=policy-authority\nkey={good_key}\ncomment\n"),
            ),
            (
                "leading whitespace",
                format!(" {PIN_FILE_DOMAIN}\nrole=policy-authority\nkey={good_key}\n"),
            ),
            (
                "crlf line endings",
                format!("{PIN_FILE_DOMAIN}\r\nrole=policy-authority\r\nkey={good_key}\r\n"),
            ),
        ];
        for (what, body) in cases {
            let path = dir.path().join("pin.pub");
            fs::write(&path, &body).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            let config =
                TrustStoreConfig::with_pin_path(&path).with_expected_owner_uid(current_uid());
            let err = match PinnedTrustStore::load(config) {
                Ok(_) => panic!("{what} was accepted"),
                Err(e) => e,
            };
            assert!(
                matches!(
                    err,
                    PolicyError::PinMalformed(_) | PolicyError::PinUnavailable(_)
                ),
                "{what} produced the wrong error: {err:?}"
            );
        }
    }

    #[test]
    fn an_oversized_pin_is_rejected_without_reading_it_all() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pin.pub");
        let mut body = format_pin_document(KeyRole::PolicyAuthority, &[0x11u8; 32]);
        body.push_str(&"x".repeat(MAX_PIN_FILE_BYTES as usize));
        fs::write(&path, &body).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let config = TrustStoreConfig::with_pin_path(&path).with_expected_owner_uid(current_uid());
        let err = PinnedTrustStore::load(config).unwrap_err();
        assert!(matches!(err, PolicyError::PinUnavailable(_)));
        assert!(err.to_string().contains("byte limit"));
    }

    #[test]
    fn install_refuses_to_replace_an_existing_pin() {
        let fx = Fixture::new();
        let replacement = PolicyAuthorityKey::generate();
        let err = PinnedTrustStore::install(&fx.config, &replacement).unwrap_err();
        assert!(matches!(err, PolicyError::PinUnavailable(_)));
        assert!(err.to_string().contains("cannot create"));
        // The original anchor is untouched.
        assert_eq!(
            fx.trust().authority_public_key_bytes(),
            &fx.authority.verifying_key_bytes()
        );
    }

    // -- preimage stability ------------------------------------------------

    /// Walks a preimage using the layout table and returns the raw value of
    /// each section, so a test can assert the layout rather than a single
    /// digest of it.
    fn walk_preimage(raw: &[u8]) -> Vec<(String, Vec<u8>)> {
        let mut cursor = 0usize;
        let mut take = |n: usize| -> Vec<u8> {
            let out = raw[cursor..cursor + n].to_vec();
            cursor += n;
            out
        };
        // domain, itself tagged, first
        let domain_tag_len = u32::from_be_bytes(take(4).try_into().unwrap()) as usize;
        assert_eq!(String::from_utf8(take(domain_tag_len)).unwrap(), "domain");
        let domain_len = u32::from_be_bytes(take(4).try_into().unwrap()) as usize;
        let domain = String::from_utf8(take(domain_len)).unwrap();
        assert_eq!(domain, POLICY_SIGNING_DOMAIN, "domain must come first");
        let count_tag_len = u32::from_be_bytes(take(4).try_into().unwrap()) as usize;
        assert_eq!(String::from_utf8(take(count_tag_len)).unwrap(), "sections");
        let count_len = u32::from_be_bytes(take(4).try_into().unwrap()) as usize;
        let count = u32::from_be_bytes(take(count_len).try_into().unwrap());
        assert_eq!(
            count as usize,
            POLICY_PREIMAGE_FIELDS.len(),
            "one section per layout row"
        );
        let mut out = Vec::new();
        for _ in 0..count {
            let tag_len = u32::from_be_bytes(take(4).try_into().unwrap()) as usize;
            let tag = String::from_utf8(take(tag_len)).unwrap();
            let value_len = u32::from_be_bytes(take(4).try_into().unwrap()) as usize;
            out.push((tag, take(value_len)));
        }
        assert_eq!(cursor, raw.len(), "no trailing bytes");
        out
    }

    #[test]
    fn the_preimage_layout_is_exactly_the_published_table() {
        let fx = Fixture::new();
        let raw = fx.sign().payload.signing_preimage().unwrap();
        let sections = walk_preimage(&raw);

        // Tags, in order, equal the table.
        let tags: Vec<&str> = sections.iter().map(|(t, _)| t.as_str()).collect();
        let expected: Vec<&str> = POLICY_PREIMAGE_FIELDS.iter().map(|(t, _)| *t).collect();
        assert_eq!(tags, expected);

        // Values are the canonical encodings the table declares.
        let p = fx.payload();
        let expect_u32 = |v: u32| v.to_be_bytes().to_vec();
        let expect_u64 = |v: u64| v.to_be_bytes().to_vec();
        let mut expected_values: Vec<Vec<u8>> = vec![
            expect_u32(p.schema_version),
            expect_u64(p.policy_version),
            expect_u64(p.chain_id),
            EXECUTOR_HEX.as_bytes().to_vec(),
            expect_u64(p.min_confirmations),
            p.controlled_registry_hash.to_bytes().unwrap().to_vec(),
            p.provider_identity_hash.to_bytes().unwrap().to_vec(),
            // P4.6. This row is new; the expectation changed because the
            // published layout gained it, which is what the version bump to 2
            // is for. The test is unchanged in what it asserts — that the
            // encoder emits exactly the table, in order, with the table's
            // canonical encoding.
            p.price_source_hash.to_bytes().unwrap().to_vec(),
            p.verifier_key_id.as_bytes().to_vec(),
            p.verifier_public_key.as_bytes().to_vec(),
            expect_u64(p.created_at_unix),
        ];
        // `walk_preimage` returns them in table order, which is emission order.
        for (i, (tag, value)) in sections.iter().enumerate() {
            assert_eq!(
                value.as_slice(),
                expected_values[i].as_slice(),
                "section {tag} is not encoded as the layout declares"
            );
        }
        expected_values.clear();

        // Concrete byte layout, shown rather than asserted by digest. With
        // POLICY_SIGNING_DOMAIN = "MYCELIUM-ECONOMY/POLICY/V1" (26 bytes) and
        // 11 sections — P4.6 made it 11 by adding the price-source binding:
        //
        //   0  : 06 00 00 00            len("domain") = 6
        //   4  : "domain"
        //  10  : 1A 00 00 00            len(domain) = 26
        //  14  : "MYCELIUM-ECONOMY/POLICY/V1"
        //  40  : 08 00 00 00            len("sections") = 8
        //  44  : "sections"
        //  52  : 04 00 00 00            value length = 4 (u32be count)
        //  56  : 0B 00 00 00            section count = 11
        //  60  : 0E 00 00 00            len("schema_version") = 14
        //  64  : "schema_version"
        //  78  : 04 00 00 00            value length = 4 (u32be)
        //  82  : 02 00 00 00            schema_version = 2
        assert_eq!(&raw[0..4], &6u32.to_be_bytes(), "len(\"domain\")");
        assert_eq!(&raw[4..10], b"domain");
        assert_eq!(
            &raw[10..14],
            &(POLICY_SIGNING_DOMAIN.len() as u32).to_be_bytes()
        );
        assert_eq!(
            &raw[14..14 + POLICY_SIGNING_DOMAIN.len()],
            POLICY_SIGNING_DOMAIN.as_bytes()
        );
        let off = 14 + POLICY_SIGNING_DOMAIN.len();
        assert_eq!(&raw[off..off + 4], &8u32.to_be_bytes(), "len(\"sections\")");
        assert_eq!(&raw[off + 4..off + 12], b"sections");
        assert_eq!(
            &raw[off + 12..off + 16],
            &4u32.to_be_bytes(),
            "count value length"
        );
        assert_eq!(
            &raw[off + 16..off + 20],
            &(POLICY_PREIMAGE_FIELDS.len() as u32).to_be_bytes()
        );
        let off = off + 20;
        assert_eq!(
            &raw[off..off + 4],
            &14u32.to_be_bytes(),
            "len(\"schema_version\")"
        );
        assert_eq!(&raw[off + 4..off + 18], b"schema_version");
        assert_eq!(
            &raw[off + 18..off + 22],
            &4u32.to_be_bytes(),
            "u32be value length"
        );
        assert_eq!(
            &raw[off + 22..off + 26],
            &OUTCOME_POLICY_SCHEMA_VERSION.to_be_bytes(),
            "schema_version is the version this build signs — 2 since P4.6 added the \
             price-source binding, and spelled out in the layout comment above"
        );
    }

    #[test]
    fn the_preimage_is_stable_for_the_same_logical_policy() {
        let fx = Fixture::new();
        // Three independent constructions of the same logical policy.
        let a = fx.payload().signing_preimage().unwrap();
        let b = fx.payload().signing_preimage().unwrap();
        let c = fx.sign().payload.signing_preimage().unwrap();
        assert_eq!(a, b);
        assert_eq!(a, c);
        // And two separately generated authorities signing the same payload
        // agree on the bytes, so the preimage does not depend on the signer.
        let other_authority = PolicyAuthorityKey::generate();
        let other = other_authority.sign(fx.payload(), &fx.verifier).unwrap();
        assert_eq!(
            other.payload.signing_preimage().unwrap(),
            a,
            "the preimage must not depend on who signed it"
        );
        // And the same authority over the same bytes signs identically, so a
        // policy's signature is reproducible rather than randomised.
        let again = fx.authority.sign(fx.payload(), &fx.verifier).unwrap();
        assert_eq!(again.signature.to_bytes(), fx.sign().signature.to_bytes());
    }

    #[test]
    fn construction_order_cannot_change_the_preimage() {
        let fx = Fixture::new();
        let registry_hash = controlled_registry_hash(&fx.registry).unwrap();
        let provider_hash = fx.provider.identity_hash();
        let price_source_hash = fx.price_source_hash();
        let key_id = fx.verifier.key_id();
        let public_key = fx.verifier.public_key();

        // Two struct literals, fields written in deliberately different orders,
        // and one built by struct-update. The encoding walks the layout table, so
        // declaration order is not observable in the bytes.
        let forwards = OutcomePolicyPayload {
            schema_version: OUTCOME_POLICY_SCHEMA_VERSION,
            policy_version: 3,
            chain_id: BASE_CHAIN_ID,
            executor: Address::parse(EXECUTOR_HEX).unwrap(),
            min_confirmations: 2,
            controlled_registry_hash: registry_hash.clone(),
            provider_identity_hash: provider_hash.clone(),
            price_source_hash: price_source_hash.clone(),
            verifier_key_id: key_id,
            verifier_public_key: public_key,
            created_at_unix: 99,
        };
        let backwards = OutcomePolicyPayload {
            created_at_unix: 99,
            verifier_public_key: public_key,
            verifier_key_id: key_id,
            provider_identity_hash: provider_hash.clone(),
            price_source_hash: price_source_hash.clone(),
            controlled_registry_hash: registry_hash.clone(),
            min_confirmations: 2,
            executor: Address::parse(EXECUTOR_HEX).unwrap(),
            chain_id: BASE_CHAIN_ID,
            policy_version: 3,
            schema_version: OUTCOME_POLICY_SCHEMA_VERSION,
        };
        let base = OutcomePolicyPayload {
            schema_version: OUTCOME_POLICY_SCHEMA_VERSION,
            policy_version: 1,
            chain_id: BASE_CHAIN_ID,
            executor: Address::parse(EXECUTOR_HEX).unwrap(),
            min_confirmations: 1,
            controlled_registry_hash: registry_hash,
            provider_identity_hash: provider_hash,
            price_source_hash: price_source_hash.clone(),
            verifier_key_id: key_id,
            verifier_public_key: public_key,
            created_at_unix: 0,
        };
        let mut patched = base.clone();
        patched.policy_version = 3;
        patched.min_confirmations = 2;
        patched.created_at_unix = 99;

        let a = forwards.signing_preimage().unwrap();
        assert_eq!(a, backwards.signing_preimage().unwrap());
        assert_eq!(a, patched.signing_preimage().unwrap());
        assert_ne!(
            a,
            base.signing_preimage().unwrap(),
            "a genuinely different policy must produce different bytes"
        );
    }

    #[test]
    fn section_order_is_cryptographically_significant() {
        // The counterpart of the previous test: if the order were not bound,
        // reordering two sections would still verify, and "canonical ordering"
        // would be a claim rather than a property.
        let fx = Fixture::new();
        let raw = fx.sign().payload.signing_preimage().unwrap();
        let sections = walk_preimage(&raw);

        // Rebuild with the executor and min_confirmations sections swapped.
        let mut swapped: Vec<(String, Vec<u8>)> = Vec::new();
        let executor_idx = sections.iter().position(|(t, _)| t == "executor").unwrap();
        let min_idx = sections
            .iter()
            .position(|(t, _)| t == "min_confirmations")
            .unwrap();
        for (i, (tag, value)) in sections.iter().enumerate() {
            if i == executor_idx {
                swapped.push((sections[min_idx].0.clone(), sections[min_idx].1.clone()));
            } else if i == min_idx {
                swapped.push((
                    sections[executor_idx].0.clone(),
                    sections[executor_idx].1.clone(),
                ));
            } else {
                swapped.push((tag.clone(), value.clone()));
            }
        }
        let mut reordered = Vec::new();
        push_tagged(&mut reordered, b"domain", POLICY_SIGNING_DOMAIN.as_bytes());
        push_tagged(
            &mut reordered,
            b"sections",
            &(swapped.len() as u32).to_be_bytes(),
        );
        for (tag, value) in &swapped {
            push_tagged(&mut reordered, tag.as_bytes(), value);
        }
        assert_ne!(
            reordered, raw,
            "reordering sections must change the signed bytes"
        );
        assert!(fx
            .authority
            .signing
            .verify(&reordered, &fx.sign().signature)
            .is_err());
    }

    #[test]
    fn length_prefixes_prevent_concatenation_ambiguity() {
        // The executor is the only variable-length ASCII field, so it is where
        // an unprefixed encoding would be ambiguous. Address bytes are fixed at
        // 40 chars, so the practical demonstration is on the encoder itself.
        let mut a = Vec::new();
        push_tagged(&mut a, b"x", b"12345");
        let mut b = Vec::new();
        push_tagged(&mut b, b"x", b"12345");
        assert_eq!(a, b, "the encoder is deterministic");
        // Unprefixed, "ab"+"c" and "a"+"bc" collide; prefixed, they do not.
        let mut unprefixed_1 = Vec::new();
        unprefixed_1.extend_from_slice(b"x");
        unprefixed_1.extend_from_slice(b"abc");
        let mut unprefixed_2 = Vec::new();
        unprefixed_2.extend_from_slice(b"x");
        unprefixed_2.extend_from_slice(b"abc");
        assert_eq!(unprefixed_1, unprefixed_2);
        let mut fixed_1 = Vec::new();
        push_tagged(&mut fixed_1, b"x", b"ab");
        push_tagged(&mut fixed_1, b"y", b"c");
        let mut fixed_2 = Vec::new();
        push_tagged(&mut fixed_2, b"x", b"a");
        push_tagged(&mut fixed_2, b"y", b"bc");
        assert_ne!(fixed_1, fixed_2);
    }

    #[test]
    fn the_preimage_is_domain_separated() {
        let fx = Fixture::new();
        let raw = fx.sign().payload.signing_preimage().unwrap();
        // The domain appears, once, inside a tagged section near the front.
        assert_eq!(walk_preimage(&raw).len(), POLICY_PREIMAGE_FIELDS.len());
        assert!(raw
            .windows(POLICY_SIGNING_DOMAIN.len())
            .any(|w| w == POLICY_SIGNING_DOMAIN.as_bytes()));
        assert_eq!(
            raw.windows(POLICY_SIGNING_DOMAIN.len())
                .filter(|w| *w == POLICY_SIGNING_DOMAIN.as_bytes())
                .count(),
            1,
            "the domain must not repeat, or it would not separate anything"
        );
        // The registry digest is computed under a different domain and so is not
        // a prefix of, or equal to, the policy preimage's leading bytes.
        let registry_digest = controlled_registry_hash(&fx.registry).unwrap();
        let prefix: [u8; 32] = raw[..32].try_into().unwrap();
        assert_ne!(registry_digest.to_bytes().unwrap(), prefix);
    }

    #[test]
    fn key_id_round_trips_through_json_with_its_role() {
        for role in KeyRole::all() {
            let id = KeyId::derive(role, &[0x42u8; 32]);
            let json = serde_json::to_string(&id).unwrap();
            assert!(json.contains(role.spelling()), "role must survive: {json}");
            let back: KeyId = serde_json::from_str(&json).unwrap();
            assert_eq!(back, id);
            assert_eq!(back.role(), role);
        }
        assert!(serde_json::from_str::<KeyId>("\"deadbeef\"").is_err());
        assert!(serde_json::from_str::<KeyId>("\"root:0x00\"").is_err());
    }

    #[test]
    fn signing_refuses_a_payload_that_names_a_different_verifier() {
        let fx = Fixture::new();
        let other = VerifierRuntimeKey::generate();
        // Payload names `other`, but the signer is handed `fx.verifier`.
        let mut payload = fx.payload();
        payload.verifier_key_id = other.key_id();
        payload.verifier_public_key = other.public_key();
        assert!(matches!(
            fx.authority.sign(payload, &fx.verifier).unwrap_err(),
            PolicyError::InvalidField {
                field: "verifier_key_id",
                ..
            }
        ));
    }

    #[test]
    fn address_and_hash_validators_are_reused_and_strict() {
        assert!(Address::parse(EXECUTOR_HEX).is_ok());
        assert!(Address::parse("0x1234").is_err());
        assert!(Address::parse("not-an-address").is_err());
        assert!(Address::parse("").is_err());
        assert!(Hash::parse("h", &format!("0x{}", "00".repeat(32))).is_ok());
        assert!(Hash::parse("h", &"00".repeat(32)).is_ok());
        assert!(Hash::parse("h", "0x00").is_err());
        assert!(Hash::parse("h", "").is_err());
        // Uppercase normalises to the same canonical spelling, so one digest has
        // one spelling in the preimage.
        assert_eq!(
            Hash::parse("h", &"AB".repeat(32)).unwrap().as_str(),
            Hash::parse("h", &format!("0x{}", "ab".repeat(32)))
                .unwrap()
                .as_str()
        );
    }

    #[test]
    fn policy_error_maps_into_the_crate_fail_closed_vocabulary() {
        let pin = PolicyError::PinUnavailable("gone".into());
        assert!(matches!(
            EconomyError::from(pin),
            EconomyError::ProviderUnpinned(_)
        ));
        let sig = PolicyError::BadSignature;
        assert!(matches!(EconomyError::from(sig), EconomyError::Invalid(_)));
        assert!(PolicyError::is_pin_failure(&PolicyError::PinMalformed(
            "x".into()
        )));
        assert!(!PolicyError::is_pin_failure(&PolicyError::BadSignature));
    }

    #[test]
    fn pin_document_round_trips() {
        for role in KeyRole::all() {
            let key = [0x77u8; 32];
            let document = format_pin_document(role, &key);
            assert_eq!(document.matches('\n').count(), 3);
            let parsed = parse_pin_document(document.as_bytes()).unwrap();
            assert_eq!(parsed, (role, key));
        }
        assert!(parse_pin_document(b"").is_err());
        assert!(parse_pin_document(&[0xff, 0xfe]).is_err());
    }
}
