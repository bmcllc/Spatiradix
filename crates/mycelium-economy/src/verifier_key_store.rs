//! Where the delegated verifier's **signing** key comes from, operationally.
//!
//! P4a made [`crate::policy_auth::ValidatedOutcomePolicy`] the only way to reach
//! a [`crate::policy_auth::VerifierRuntimeKey`]'s identity, and P4b/P4c made that
//! key the only thing that can mint an
//! [`crate::receipt_auth::AuthenticatedExternalValueReceipt`] or an
//! [`crate::settlement_auth::AuthenticatedSettlementReceipt`]. What none of those
//! modules decide — because a library cannot — is where an *operator's* process
//! finds the private half of that key on disk. This module is that decision.
//!
//! # Why the key does not live in the economy directory
//!
//! The obvious place, `~/.mycelium/economy/`, is the one place it must never be:
//! that directory is the untrusted-input boundary this crate exists to defend.
//! A process able to write the ledgers can already forge settlements and
//! receipts; giving it the signing key as well would let it produce artefacts
//! that pass every signature check, converting "the storage layer was rewritten"
//! from a detectable state into an undetectable one. The settlement
//! attestation ledger lives there, which is precisely why it must not also hold
//! the key that signs into it.
//!
//! # Why the key is not a second, independent trust anchor
//!
//! The key is placed **in the same trust root as the policy-authority pin** and
//! nothing else. That is the whole design, and it is deliberate:
//!
//! * A valid policy already names the signing key (`verifier_key_id` +
//!   `verifier_public_key`), and that pair is covered by the authority
//!   signature and checked against the pinned authority. So the policy, not
//!   this module, is what says which key is allowed to sign.
//! * Therefore a key planted at any path this module can be made to read is
//!   still inert: [`load_bound_verifier_runtime_key`] refuses unless its
//!   `key_id()` is the one the *validated* policy delegates to, and
//!   `attest_settlement`/`attest` refuse the same thing independently.
//! * Because the pin and the key sit behind one directory, planting a key
//!   without authority to sign it is possible; *authorising* it requires
//!   replacing the pin and serving a policy signed by the matching authority
//!   private key, which is not in this repository. One directory, one
//!   decision, both halves of the authenticated-policy layer move together —
//!   there is no configuration in which the authority is pinned as root but the
//!   signing key sits in a home directory.
//!
//! # The relocation opt-in, and what it costs
//!
//! The default trust root is [`DEFAULT_TRUST_ROOT_DIR`], owned by root, and
//! [`DEFAULT_POLICY_AUTHORITY_PIN_UID`] is the uid required to own files in it.
//! A host where `/etc/mycelium/trust` is not creatable — including any
//! unprivileged deployment — cannot sign at all under the default. That is the
//! intended fail-closed behaviour: **the CLI refuses to sign unless an operator
//! has explicitly pointed [`TRUST_ROOT_ENV`] at a trust root they provisioned.**
//!
//! What the opt-in gives up, stated plainly because it is real: a relocated
//! trust root is a directory the invoking principal controls. Anyone able to
//! write it can replace the pin *and* the signing key and serve a policy they
//! signed themselves, at which point this CLI will sign for them. That is not a
//! new class of failure — the read side already has exactly this exposure if
//! the pin is relocated, and P4a owns it — but attaching the *private* key to
//! the same directory widens what a successful replacement buys. Every trust
//! report therefore carries [`TrustRoot::relocated`] so the state is visible in
//! the command output rather than inferred from a path.
//!
//! # What is enforced here and what is not
//!
//! Enforced: absolute path, no symlink, regular file, size limit, no group or
//! other permission bits, expected owner uid, exact three-line grammar, role
//! pinned to `verifier-runtime`, and — the load-bearing one — identity binding
//! to the validated policy.
//!
//! Not enforced, and not claimed anywhere: that the key is the *same* value an
//! operator intended. Nothing here can tell an honest key from a substituted
//! one whose identity the policy also names; that question is answered by the
//! pin, not by the filesystem.

use crate::policy_auth::{
    KeyRole, PolicyError, TrustStoreConfig, ValidatedOutcomePolicy,
    VerifierRuntimeKey, DEFAULT_POLICY_AUTHORITY_PIN_PATH,
    DEFAULT_POLICY_AUTHORITY_PIN_UID,
};
use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

/// Default trust root: the directory the pinned policy authority lives in, and
/// therefore also where the verifier runtime key belongs.
pub const DEFAULT_TRUST_ROOT_DIR: &str = "/etc/mycelium/trust";

/// File name of the verifier runtime signing key inside the trust root.
pub const VERIFIER_KEY_FILE: &str = "verifier-runtime.key";

/// Operator opt-in that relocates the whole trust root.
///
/// Setting it moves **both** the policy authority pin and the verifier signing
/// key, which is the point: one variable, one decision, both halves of the
/// authenticated-policy layer. An unset or empty value is the system default,
/// which is the fail-closed case for signing.
///
/// See the module documentation for what this gives up.
pub const TRUST_ROOT_ENV: &str = "MYCELIUM_TRUST_ROOT_DIR";

/// First line of the verifier runtime key file. A file that does not start with
/// this is not a key, whatever else it contains. A different string from
/// [`crate::policy_auth`]'s pin domain on purpose, so a pin can never be
/// presented as a key or the reverse.
const VERIFIER_KEY_DOMAIN: &str = "MYCELIUM-ECONOMY/VERIFIER-RUNTIME-KEY/V1";

/// Size limit on the key file. The document is a fixed three short lines; a file
/// this size is not one.
const MAX_VERIFIER_KEY_FILE_BYTES: u64 = 256;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Every way loading the signing key can fail.
///
/// The variants are separate because the operator's remedy is different for
/// each, and an operator who is told "signing key unavailable" has learned
/// nothing they can act on.
#[derive(Debug, thiserror::Error)]
pub enum VerifierKeyError {
    /// The key file is not there. The common case on a host that has never
    /// provisioned a signing key, and never a silent one.
    #[error(
        "no verifier runtime signing key at {path}; this process cannot sign \
         settlements or external-value receipts. The key is delegated by the \
         signed outcome policy, so provision it under the trust root \
         {trust_root} as {file} with mode 0400 and the expected owner \
         (uid {expected_uid}), or point {env} at the trust root you \
         provisioned"
    )]
    NotConfigured {
        path: PathBuf,
        trust_root: PathBuf,
        file: &'static str,
        expected_uid: u32,
        env: &'static str,
    },

    /// The path exists but failed a filesystem identity check. A distinct
    /// variant from `NotConfigured` because the operator's file *is* there and
    /// the problem is its mode, owner or type.
    #[error("verifier runtime signing key {path} is unusable: {detail}")]
    Unavailable { path: PathBuf, detail: String },

    /// The bytes are not a key document.
    #[error("verifier runtime signing key {path} is malformed: {detail}")]
    Malformed { path: PathBuf, detail: String },

    /// The key's identity is not the one the validated policy delegates to.
    ///
    /// The refusal that makes a planted key inert, and the one an operator hits
    /// most often after a legitimate key rotation they have not finished.
    #[error(
        "the verifier runtime key at {path} is {key_id}, but the validated \
         outcome policy delegates to {delegated}. Refusing to sign: a key no \
         validated policy delegated to must not be able to mint \
         attestations. Either the policy needs re-signing for this key, or the \
         key file is stale"
    )]
    NotDelegated {
        path: PathBuf,
        key_id: String,
        delegated: String,
    },

    #[error(transparent)]
    Policy(#[from] PolicyError),
}

// ---------------------------------------------------------------------------
// The trust root
// ---------------------------------------------------------------------------

/// Where the authenticated-policy layer's files live, and who must own them.
///
/// Two files, one directory: the policy authority *pin* (public, P4a) and the
/// verifier runtime *key* (private, this module). Keeping them together is the
/// design; see the module documentation for why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustRoot {
    dir: PathBuf,
    expected_owner_uid: u32,
    relocated: bool,
}

impl TrustRoot {
    /// The system default: `/etc/mycelium/trust`, files owned by root.
    ///
    /// Unusable for signing on any host that cannot write `/etc`, which is the
    /// fail-closed case and not an oversight.
    pub fn system_default() -> Self {
        Self {
            dir: PathBuf::from(DEFAULT_TRUST_ROOT_DIR),
            expected_owner_uid: DEFAULT_POLICY_AUTHORITY_PIN_UID,
            relocated: false,
        }
    }

    /// An explicitly provisioned trust root, owned by `expected_owner_uid`.
    pub fn at(dir: impl Into<PathBuf>, expected_owner_uid: u32) -> Self {
        Self {
            dir: dir.into(),
            expected_owner_uid,
            relocated: true,
        }
    }

    /// The trust root this process should use.
    ///
    /// [`TRUST_ROOT_ENV`] when set to a non-empty value, the system default
    /// otherwise. A relocation whose owner cannot be determined — an unreadable
    /// `/proc/self`, which is not reachable on Linux but is reachable in a
    /// sufficiently broken sandbox — refuses to a root-owned root rather than
    /// guessing, so a relocation can never silently widen the uid check.
    pub fn resolve() -> Self {
        let raw = std::env::var(TRUST_ROOT_ENV).unwrap_or_default();
        let raw = raw.trim();
        if raw.is_empty() {
            return Self::system_default();
        }
        match current_uid() {
            Some(uid) => Self::at(raw, uid),
            None => Self {
                dir: PathBuf::from(raw),
                expected_owner_uid: DEFAULT_POLICY_AUTHORITY_PIN_UID,
                relocated: true,
            },
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn expected_owner_uid(&self) -> u32 {
        self.expected_owner_uid
    }

    /// Whether an operator pointed [`TRUST_ROOT_ENV`] at this directory.
    ///
    /// Reported in every trust report: a relocated trust root is a directory the
    /// invoking principal controls, which is a weaker posture than the root-owned
    /// default and should be visible rather than inferred from a path.
    pub fn relocated(&self) -> bool {
        self.relocated
    }

    /// The pinned policy authority public key.
    ///
    /// The default resolves to exactly
    /// [`DEFAULT_POLICY_AUTHORITY_PIN_PATH`]; the file name is taken from that
    /// constant so there is one spelling of it in the crate.
    pub fn pin_path(&self) -> PathBuf {
        self.dir.join(pin_file_name())
    }

    /// The verifier runtime signing key.
    pub fn verifier_key_path(&self) -> PathBuf {
        self.dir.join(VERIFIER_KEY_FILE)
    }

    /// The pin's configuration, for [`crate::policy_auth::PinnedTrustStore`].
    pub fn trust_store_config(&self) -> TrustStoreConfig {
        TrustStoreConfig::with_pin_path(self.pin_path())
            .with_expected_owner_uid(self.expected_owner_uid)
    }

    /// The signing key's configuration.
    pub fn key_store_config(&self) -> VerifierKeyStoreConfig {
        VerifierKeyStoreConfig {
            key_path: self.verifier_key_path(),
            expected_owner_uid: self.expected_owner_uid,
        }
    }

    /// Rejects a trust root that could not possibly be a trust root, so a
    /// misconfiguration fails at resolution rather than at load with a message
    /// about a file that never existed.
    pub fn validate_shape(&self) -> Result<(), VerifierKeyError> {
        let dir = &self.dir;
        if dir.as_os_str().is_empty() {
            return Err(VerifierKeyError::Unavailable {
                path: dir.clone(),
                detail: format!(
                    "{TRUST_ROOT_ENV} is empty; there is no default trust root \
                     and no fallback"
                ),
            });
        }
        if !dir.is_absolute() {
            return Err(VerifierKeyError::Unavailable {
                path: dir.clone(),
                detail: format!(
                    "trust root must be an absolute path, got {}",
                    dir.display()
                ),
            });
        }
        Ok(())
    }
}

fn pin_file_name() -> &'static str {
    DEFAULT_POLICY_AUTHORITY_PIN_PATH
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or("policy-authority.pub")
}

fn current_uid() -> Option<u32> {
    fs::metadata("/proc/self").ok().map(|m| m.uid())
}

// ---------------------------------------------------------------------------
// The key store
// ---------------------------------------------------------------------------

/// Where the verifier runtime key lives and who must own it. Only the path and
/// the expected owner are configurable; whether the path is a regular file,
/// whether the mode is private, and what happens when the file is missing are
/// all fixed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierKeyStoreConfig {
    key_path: PathBuf,
    expected_owner_uid: u32,
}

impl VerifierKeyStoreConfig {
    pub fn new(key_path: impl Into<PathBuf>, expected_owner_uid: u32) -> Self {
        Self {
            key_path: key_path.into(),
            expected_owner_uid,
        }
    }

    pub fn key_path(&self) -> &Path {
        &self.key_path
    }

    pub fn expected_owner_uid(&self) -> u32 {
        self.expected_owner_uid
    }
}

/// Restores a verifier runtime key from its stored seed and writes it to the
/// configured path.
///
/// Operator-side, and the analogue of
/// [`crate::policy_auth::PinnedTrustStore::install`]. The file is created with
/// `create_new` — it can never silently replace an existing signing key — with
/// mode `0400`, and is then re-read through the same checks
/// [`load_verifier_runtime_key`] applies. Ownership is not changed, so a key
/// this process installs under its own uid must be configured with that uid as
/// the expected owner; see [`TrustRoot::at`].
///
/// Takes the seed rather than a [`VerifierRuntimeKey`] on purpose: there is
/// deliberately no public accessor for a key's secret bytes, and
/// [`VerifierRuntimeKey`]'s `Debug` redacts them. Adding one here to make an
/// install path prettier would undo that.
pub fn install_verifier_runtime_key(
    config: &VerifierKeyStoreConfig,
    seed: [u8; 32],
) -> Result<(), VerifierKeyError> {
    if let Some(parent) = config.key_path.parent() {
        // Best effort: an existing, correct directory is left alone. A missing
        // one is reported by the `create_new` below.
        let _ = fs::create_dir_all(parent);
    }
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(&config.key_path)
        .map_err(|e| VerifierKeyError::Unavailable {
            path: config.key_path.clone(),
            detail: format!("cannot create verifier runtime key: {e}"),
        })?
        .write_all(format_key_document(&hex::encode(seed)).as_bytes())
        .map_err(|e| VerifierKeyError::Unavailable {
            path: config.key_path.clone(),
            detail: format!("cannot write verifier runtime key: {e}"),
        })?;
    load_verifier_runtime_key(config).map(|_| ())
}

/// Reads and validates the signing key, with no policy in hand.
///
/// Returns the key on its own identity. Prefer
/// [`load_bound_verifier_runtime_key`], which is the one that cannot return an
/// unauthorised key; this exists for diagnostics that need to *report* a key
/// without authorising anything.
pub fn load_verifier_runtime_key(
    config: &VerifierKeyStoreConfig,
) -> Result<VerifierRuntimeKey, VerifierKeyError> {
    let path = &config.key_path;

    // Stage 1: path identity, via lstat.
    let meta = fs::symlink_metadata(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            VerifierKeyError::NotConfigured {
                path: path.clone(),
                trust_root: parent_dir(path),
                file: VERIFIER_KEY_FILE,
                expected_uid: config.expected_owner_uid,
                env: TRUST_ROOT_ENV,
            }
        } else {
            VerifierKeyError::Unavailable {
                path: path.clone(),
                detail: format!("signing key is unusable: {e}"),
            }
        }
    })?;
    if meta.file_type().is_symlink() {
        return Err(VerifierKeyError::Unavailable {
            path: path.clone(),
            detail: "is a symlink; ownership of the target would not be \
                     checkable at the pinned path"
                .into(),
        });
    }
    if !meta.file_type().is_file() {
        return Err(VerifierKeyError::Unavailable {
            path: path.clone(),
            detail: "is not a regular file".into(),
        });
    }
    if meta.len() > MAX_VERIFIER_KEY_FILE_BYTES {
        return Err(VerifierKeyError::Unavailable {
            path: path.clone(),
            detail: format!(
                "is {} bytes, over the {MAX_VERIFIER_KEY_FILE_BYTES}-byte limit",
                meta.len()
            ),
        });
    }
    check_key_mode_and_owner(&meta, config)?;

    // Stage 2: descriptor identity, via fstat on the opened file. `open(2)`
    // follows symlinks, so stage 1 alone leaves a window in which the path is
    // replaced; re-reading `fstat(2)` on the opened inode means the ownership
    // and mode actually verified are those of the bytes actually read. The same
    // two-stage technique `read_pin_document` uses.
    let file = File::open(path).map_err(|e| VerifierKeyError::Unavailable {
        path: path.clone(),
        detail: format!("is unreadable: {e}"),
    })?;
    let opened = file.metadata().map_err(|e| VerifierKeyError::Unavailable {
        path: path.clone(),
        detail: format!("has no readable metadata: {e}"),
    })?;
    if !opened.file_type().is_file() {
        return Err(VerifierKeyError::Unavailable {
            path: path.clone(),
            detail: "did not open as a regular file".into(),
        });
    }
    check_key_mode_and_owner(&opened, config)?;

    let mut raw = Vec::new();
    file.take(MAX_VERIFIER_KEY_FILE_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(|e| VerifierKeyError::Unavailable {
            path: path.clone(),
            detail: format!("is unreadable: {e}"),
        })?;
    if raw.len() as u64 > MAX_VERIFIER_KEY_FILE_BYTES {
        return Err(VerifierKeyError::Unavailable {
            path: path.clone(),
            detail: format!(
                "exceeds the {MAX_VERIFIER_KEY_FILE_BYTES}-byte limit"
            ),
        });
    }
    let seed = parse_key_document(&raw, path)?;
    Ok(VerifierRuntimeKey::from_seed(seed))
}

/// Reads the signing key and refuses it unless a **validated** policy delegates
/// to it.
///
/// This is the fail-closed point for the whole signing path, and it is
/// deliberately here rather than in the CLI:
///
/// 1. There is no way to obtain a `ValidatedOutcomePolicy` other than
///    [`crate::policy_auth::validate_outcome_policy`], so the binding can only
///    be checked against a policy whose authority came from the pinned anchor.
/// 2. It runs *before* any signature is produced, so a key that would be
///    refused by `attest_settlement` never reaches the signing path and the
///    operator gets this error — which names both key ids and says what to do —
///    instead of the generic downstream refusal.
/// 3. `attest_settlement` and `VerifierRuntimeKey::attest` keep their own
///    identical checks. This is defence in depth, not the only line: the
///    library check means no caller can skip it.
pub fn load_bound_verifier_runtime_key(
    policy: &ValidatedOutcomePolicy,
    config: &VerifierKeyStoreConfig,
) -> Result<VerifierRuntimeKey, VerifierKeyError> {
    let key = load_verifier_runtime_key(config)?;
    let delegated = policy.verifier_key_id();
    if key.key_id() != delegated {
        return Err(VerifierKeyError::NotDelegated {
            path: config.key_path.clone(),
            key_id: key.key_id().to_string(),
            delegated: delegated.to_string(),
        });
    }
    Ok(key)
}

fn check_key_mode_and_owner(
    meta: &Metadata,
    config: &VerifierKeyStoreConfig,
) -> Result<(), VerifierKeyError> {
    // Stricter than the pin on purpose: the pin is a public key, this is a
    // private one. Group- or other-readable is refused outright rather than
    // merely group/other-*writable*, because a readable private signing key is
    // already the compromise.
    let mode = meta.mode() & 0o7777;
    if mode & 0o077 != 0 {
        return Err(VerifierKeyError::Unavailable {
            path: config.key_path.clone(),
            detail: format!(
                "has mode {mode:04o}; a private signing key must not be \
                 readable by group or other (chmod 0400)"
            ),
        });
    }
    let expected = config.expected_owner_uid();
    if meta.uid() != expected {
        return Err(VerifierKeyError::Unavailable {
            path: config.key_path.clone(),
            detail: format!("is owned by uid {}, expected uid {expected}", meta.uid()),
        });
    }
    Ok(())
}

fn parent_dir(path: &Path) -> PathBuf {
    path.parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

// ---------------------------------------------------------------------------
// The key document
// ---------------------------------------------------------------------------

/// The key file's exact grammar: three LF-terminated lines, nothing else. The
/// same shape as P4a's pin so the two files read alike and an operator can tell
/// them apart by their first line.
///
/// ```text
/// MYCELIUM-ECONOMY/VERIFIER-RUNTIME-KEY/V1
/// role=verifier-runtime
/// seed=0x<64 lowercase hex>
/// ```
fn format_key_document(seed_hex: &str) -> String {
    format!(
        "{VERIFIER_KEY_DOMAIN}\nrole={}\nseed=0x{seed_hex}\n",
        KeyRole::VerifierRuntime.spelling(),
    )
}

/// Strict parser. No comments, no whitespace tolerance, no unknown lines: a key
/// file is machine-written and anything unexpected in it means the file is not
/// one.
fn parse_key_document(
    raw: &[u8],
    path: &Path,
) -> Result<[u8; 32], VerifierKeyError> {
    let malformed = |detail: String| VerifierKeyError::Malformed {
        path: path.to_path_buf(),
        detail,
    };
    let text = std::str::from_utf8(raw)
        .map_err(|_| malformed("is not valid UTF-8".into()))?;
    let lines: Vec<&str> = text.split('\n').collect();
    if lines.len() != 4 || !lines[3].is_empty() {
        return Err(malformed(format!(
            "expected 3 newline-terminated lines, found {}",
            lines.len().saturating_sub(usize::from(lines.last() == Some(&"")))
        )));
    }
    if lines[0] != VERIFIER_KEY_DOMAIN {
        return Err(malformed(format!(
            "first line is {:?}, expected {VERIFIER_KEY_DOMAIN:?}",
            lines[0]
        )));
    }
    let role_value = lines[1]
        .strip_prefix("role=")
        .ok_or_else(|| malformed(format!("line 2 is {:?}", lines[1])))?;
    let role = KeyRole::from_spelling(role_value).ok_or_else(|| {
        malformed(format!(
            "unknown key role {role_value:?} on line 2; this file holds a \
             verifier runtime key and nothing else"
        ))
    })?;
    if role != KeyRole::VerifierRuntime {
        return Err(malformed(format!(
            "this file holds a key in role {role}; only {} may be loaded as a \
             signing key",
            KeyRole::VerifierRuntime
        )));
    }
    let seed_value = lines[2]
        .strip_prefix("seed=")
        .ok_or_else(|| malformed(format!("line 3 is {:?}", lines[2])))?;
    let body = seed_value
        .strip_prefix("0x")
        .ok_or_else(|| malformed("seed= must be 0x-prefixed".into()))?;
    hex::decode(body)
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .ok_or_else(|| {
            malformed(format!(
                "seed= must be exactly 32 bytes of hex, got {} chars",
                body.len()
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn config(dir: &Path) -> VerifierKeyStoreConfig {
        VerifierKeyStoreConfig::new(dir.join(VERIFIER_KEY_FILE), current_uid().unwrap())
    }

    fn write_key(dir: &Path, seed: [u8; 32]) -> VerifierKeyStoreConfig {
        let cfg = config(dir);
        install_verifier_runtime_key(&cfg, seed).unwrap();
        cfg
    }

    #[test]
    fn system_default_is_etc_owned_and_not_relocated() {
        let root = TrustRoot::system_default();
        assert_eq!(root.dir().to_str(), Some(DEFAULT_TRUST_ROOT_DIR));
        assert_eq!(root.expected_owner_uid(), 0);
        assert!(!root.relocated());
        // The pin path must not drift from P4a's constant: one spelling only.
        assert_eq!(root.pin_path(), PathBuf::from(DEFAULT_POLICY_AUTHORITY_PIN_PATH));
        assert_eq!(root.trust_store_config().expected_owner_uid(), 0);
    }

    #[test]
    fn the_key_lives_beside_the_pin_in_one_trust_root() {
        let root = TrustRoot::at("/srv/trust", 7);
        assert_eq!(root.pin_path(), PathBuf::from("/srv/trust/policy-authority.pub"));
        assert_eq!(
            root.verifier_key_path(),
            PathBuf::from("/srv/trust/verifier-runtime.key")
        );
        assert_eq!(
            root.pin_path().parent(),
            root.verifier_key_path().parent(),
            "the key must not be able to be configured away from the pin"
        );
    }

    #[test]
    fn a_relocated_root_is_reported_as_relocated() {
        // The whole point of the field: an operator reading a trust report can
        // tell the weaker posture without inferring it from a path.
        assert!(TrustRoot::at("/tmp/trust", 1000).relocated());
    }

    #[test]
    fn a_missing_key_is_a_typed_refusal_naming_the_path_and_the_env_var() {
        let dir = tempfile::tempdir().unwrap();
        let err = load_verifier_runtime_key(&config(dir.path())).unwrap_err();
        let msg = err.to_string();
        assert!(matches!(err, VerifierKeyError::NotConfigured { .. }));
        assert!(msg.contains(VERIFIER_KEY_FILE), "{msg}");
        assert!(msg.contains(TRUST_ROOT_ENV), "{msg}");
        assert!(msg.contains("cannot sign"), "{msg}");
    }

    #[test]
    fn a_round_tripped_key_loads_and_keeps_its_identity() {
        let dir = tempfile::tempdir().unwrap();
        let seed = [0x5au8; 32];
        let cfg = write_key(dir.path(), seed);
        let loaded = load_verifier_runtime_key(&cfg).unwrap();
        assert_eq!(loaded.key_id(), VerifierRuntimeKey::from_seed(seed).key_id());
        // Installed 0400 and never widened by the write itself.
        let mode = fs::metadata(cfg.key_path()).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o400, "the key must not be group/other readable");
    }

    #[test]
    fn install_never_replaces_an_existing_key() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config(dir.path());
        install_verifier_runtime_key(&cfg, [7u8; 32]).unwrap();
        // The second install is refused rather than overwriting: replacing a
        // signing key in place is exactly what an operator must do
        // deliberately, through the policy that delegates to it.
        let err =
            install_verifier_runtime_key(&cfg, [9u8; 32]).unwrap_err();
        assert!(err.to_string().contains("File exists"), "{err}");
        assert_eq!(
            load_verifier_runtime_key(&cfg).unwrap().key_id(),
            VerifierRuntimeKey::from_seed([7u8; 32]).key_id()
        );
    }

    #[test]
    fn a_group_readable_key_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = write_key(dir.path(), [3u8; 32]);
        fs::set_permissions(cfg.key_path(), fs::Permissions::from_mode(0o440)).unwrap();
        let err = load_verifier_runtime_key(&cfg).unwrap_err();
        assert!(matches!(err, VerifierKeyError::Unavailable { .. }));
        assert!(err.to_string().contains("group or other"), "{err}");
    }

    #[test]
    fn a_wrong_owner_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = write_key(dir.path(), [4u8; 32]);
        let wrong = VerifierKeyStoreConfig::new(cfg.key_path(), current_uid().unwrap() + 1);
        let err = load_verifier_runtime_key(&wrong).unwrap_err();
        assert!(err.to_string().contains("expected uid"), "{err}");
    }

    #[test]
    fn a_symlinked_key_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let real = write_key(dir.path(), [5u8; 32]);
        let link = dir.path().join("link.key");
        std::os::unix::fs::symlink(real.key_path(), &link).unwrap();
        let cfg = VerifierKeyStoreConfig::new(link, current_uid().unwrap());
        let err = load_verifier_runtime_key(&cfg).unwrap_err();
        assert!(err.to_string().contains("symlink"), "{err}");
    }

    #[test]
    fn a_pin_document_is_not_accepted_as_a_key() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = VerifierKeyStoreConfig::new(dir.path().join(VERIFIER_KEY_FILE), current_uid().unwrap());
        fs::write(cfg.key_path(), "MYCELIUM-ECONOMY/POLICY-AUTHORITY-PIN/V1\nrole=policy-authority\nkey=0x00\n").unwrap();
        fs::set_permissions(cfg.key_path(), fs::Permissions::from_mode(0o400)).unwrap();
        let err = load_verifier_runtime_key(&cfg).unwrap_err();
        // The first line differs, so the two files cannot be presented for one
        // another at all.
        assert!(err.to_string().contains("expected \"MYCELIUM-ECONOMY/VERIFIER-RUNTIME-KEY/V1\""), "{err}");
    }

    #[test]
    fn a_trailing_comment_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = VerifierKeyStoreConfig::new(dir.path().join(VERIFIER_KEY_FILE), current_uid().unwrap());
        let doc = format!(
            "{VERIFIER_KEY_DOMAIN}\nrole=verifier-runtime\nseed=0x{}\n# mine\n",
            "11".repeat(32)
        );
        fs::write(cfg.key_path(), doc).unwrap();
        fs::set_permissions(cfg.key_path(), fs::Permissions::from_mode(0o400)).unwrap();
        assert!(matches!(
            load_verifier_runtime_key(&cfg),
            Err(VerifierKeyError::Malformed { .. })
        ));
    }

    #[test]
    fn a_relative_or_empty_trust_root_is_refused_at_resolution() {
        assert!(TrustRoot::at("relative/trust", 0).validate_shape().is_err());
        assert!(TrustRoot::at("", 0).validate_shape().is_err());
    }
}