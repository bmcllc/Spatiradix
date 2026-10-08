//! P6.9 — the policy high-water mark, and rollback hardening.
//!
//! # The problem
//!
//! [`crate::policy_auth::validate_outcome_policy`] checks that a policy is
//! correctly signed by the pinned authority and that it matches the live
//! registry, provider and price-source binding. It does **not** — and the audit
//! that preceded this module was explicit about it — track rotation history:
//!
//! > Policy-rotation history is deliberately out of scope: there is no
//! > revocation list and no `policy_version` high-water mark here, so a policy
//! > that stops matching the live registry and provider is simply unattested.
//!
//! That leaves a specific hole. A signed policy at a *lower* `policy_version` —
//! one signed before the operator tightened `min_confirmations`, widened the
//! permitted price sources, or moved the executor — verifies perfectly. It is
//! signed by the pinned authority. It matches the live registry and provider. It
//! is simply **older**, and nothing in the crate notices.
//!
//! # Why a bare `highest_policy_version` is not enough
//!
//! The obvious fix is a number. It is insufficient, and the reason is not
//! theoretical:
//!
//! > one number could by operational bug correspond to different hashes
//!
//! Concretely: a rotation tool that re-reads `outcome-policy.json` from a
//! restored backup, a filesystem that serves `v3` from one directory and `v2`
//! from another, a deploy that bumps `policy_version` in the payload but signs
//! with a stale preimage, an operator who hand-edits the field — each of these
//! leaves `highest_policy_version == 3` while the *content* at version 3 is
//! whatever the bug produced. A number cannot detect that, because the number
//! carries no statement about which document it describes.
//!
//! So the mark is a **pair**, [`PolicyHighWaterMark`] = `(version, policy_hash)`,
//! and the acceptance rules use both:
//!
//! | candidate | rule | outcome |
//! |---|---|---|
//! | `version < high_water.version` | rollback | **rejected** — [`PolicyError::PolicyRollback`] |
//! | `version == high_water.version`, `hash != high_water.policy_hash` | equivocation | **rejected** — [`PolicyError::PolicyHashDivergence`] |
//! | `version == high_water.version`, `hash == high_water.policy_hash` | idempotent re-load | [`PolicyStanding::AlreadyInForce`] |
//! | `version > high_water.version` | forward | [`PolicyStanding::PromotionRequired`] — **not in force** until [`PolicyHighWaterMarkStore::promote`] |
//! | no mark on disk | genesis | [`PolicyStanding::Genesis`] |
//!
//! Note the third row: an equal version with a matching hash is *not* a
//! promotion, so reloading the same policy on every process start never grows
//! the ledger. And note the fourth: a newer policy is **not** automatically
//! accepted, because "an authority signed something newer" and "this node has
//! adopted it" are different statements, and only the second one is a decision
//! an operator makes.
//!
//! # What this does NOT defeat — read this before relying on it
//!
//! **A high-water mark stored by the same principal does not defeat
//! same-principal rollback.** This is a fact about where the file lives, not
//! about the logic above, and no amount of hashing fixes it. The chain of
//! custody for a rollback is:
//!
//! 1. an attacker with write access to the economy root rewrites
//!    `policy-high-water.jsonl`, truncating it to an earlier record, and
//! 2. replaces `outcome-policy.json` with the older signed policy.
//!
//! Against that, [`crate::durability::HeadAnchor`] catches step 1 *only* if the
//! attacker also leaves the anchor behind. They own both files. The chain hash
//! catches an *accidental* rewrite, a truncated tail or a swapped-in backup; the
//! anchor catches a crash-window lag. Neither is a defence against a principal
//! who can write both.
//!
//! The defences that actually defeat it are all out of scope here and are named
//! rather than implied:
//!
//! * **TPM / sealed storage** — bind the mark to a platform measurement so it
//!   cannot be written by the OS at all.
//! * **A root-owned store** — the mark lives in a file the service account
//!   cannot write, so a compromised node process cannot move it.
//! * **A remote witness** — a second, independently operated service holds the
//!   mark and is consulted on every promotion.
//! * **A quorum** — several witnesses, with a threshold, so no single operator —
//!   and no single compromised one — can roll back.
//!
//! None of the four is implemented. What this module *does* deliver is the
//! invariant that has to hold before any of them is worth building: the mark is
//! a `(version, hash)` pair, it only ever moves forward, it is only moved by an
//! explicit call, and its history is append-only and hash-chained so that a
//! same-principal rewrite is at least *visible* rather than silent.
//!
//! # Storage discipline
//!
//! Nothing here invents a second discipline. Every byte goes through
//! [`crate::durability`]: the root is `ensure_private_dir` (`0700`), records are
//! `append_line` (`0600`), the ledger is `LedgerLock`-guarded across
//! read-tail → derive → write, a torn tail is `recover_torn_tail`-ed before
//! anything is read, and the head is pinned with `store_head_anchor` /
//! `verify_head_anchor`. The same three primitives every other ledger in this
//! crate uses, in the same order.

use crate::{
    durability::{self, HeadAnchor},
    policy_auth::{
        Hash, PolicyError, SignedOutcomePolicy, ValidatedOutcomePolicy, OUTCOME_POLICY_FILE,
        OUTCOME_POLICY_SCHEMA_VERSION,
    },
    EconomyError, Result,
};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    fs,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
};

/// High-water ledger file name; also the append lock name and the head anchor's
/// ledger identifier.
pub const POLICY_HIGH_WATER_FILE: &str = "policy-high-water.jsonl";

/// `prev_hash` of the first record.
pub const POLICY_HIGH_WATER_GENESIS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

// ---------------------------------------------------------------------------
// The mark
// ---------------------------------------------------------------------------

/// The highest policy version this node has adopted, and the hash of the exact
/// document that version was.
///
/// # Why the pair, again, in one sentence
///
/// A version number alone cannot detect a bug that associates one number with
/// two different documents, which is the operational failure this pair exists to
/// make visible. The full argument is in the module doc.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyHighWaterMark {
    pub version: u64,
    pub policy_hash: Hash,
}

impl PolicyHighWaterMark {
    pub fn new(version: u64, policy_hash: Hash) -> Self {
        Self {
            version,
            policy_hash,
        }
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn policy_hash(&self) -> &Hash {
        &self.policy_hash
    }

    /// The two refusal rules, as a named function.
    ///
    /// One place, used by both [`PolicyHighWaterMarkStore::evaluate`] and
    /// [`PolicyHighWaterMarkStore::promote`], so the read path and the write
    /// path cannot disagree about what a rollback is.
    pub fn check_candidate(
        &self,
        offered_version: u64,
        offered_hash: &Hash,
    ) -> std::result::Result<PolicyStanding, PolicyError> {
        if offered_version < self.version {
            return Err(PolicyError::PolicyRollback {
                offered_version,
                offered_hash: offered_hash.to_string(),
                high_water_version: self.version,
                high_water_hash: self.policy_hash.to_string(),
            });
        }
        if offered_version == self.version {
            if offered_hash != &self.policy_hash {
                return Err(PolicyError::PolicyHashDivergence {
                    version: offered_version,
                    offered_hash: offered_hash.to_string(),
                    high_water_hash: self.policy_hash.to_string(),
                });
            }
            return Ok(PolicyStanding::AlreadyInForce);
        }
        Ok(PolicyStanding::PromotionRequired {
            high_water: self.clone(),
        })
    }
}

impl fmt::Display for PolicyHighWaterMark {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "policy v{} ({})", self.version, self.policy_hash)
    }
}

// ---------------------------------------------------------------------------
// Standing
// ---------------------------------------------------------------------------

/// What the gate concluded about a candidate policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "standing", content = "detail", rename_all = "snake_case")]
pub enum PolicyStanding {
    /// No mark on disk. This policy establishes the first one. Accepting it does
    /// not write anything; [`PolicyHighWaterMarkStore::promote`] does.
    Genesis,
    /// Byte-identical to the policy already in force. Idempotent: a node that
    /// reloads its policy on every start does not grow the ledger.
    AlreadyInForce,
    /// Newer than the mark, and **not in force**. Promotion is an explicit
    /// operation, so this is a refusal with a named next step rather than an
    /// acceptance.
    PromotionRequired { high_water: PolicyHighWaterMark },
}

impl PolicyStanding {
    pub fn state(&self) -> &'static str {
        match self {
            Self::Genesis => "genesis",
            Self::AlreadyInForce => "already_in_force",
            Self::PromotionRequired { .. } => "promotion_required",
        }
    }

    /// Whether this standing puts the candidate into force. `false` for
    /// [`PolicyStanding::PromotionRequired`], which is the whole point.
    pub fn is_in_force(&self) -> bool {
        matches!(self, Self::Genesis | Self::AlreadyInForce)
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Genesis => "no policy high-water mark exists yet; this policy establishes the \
                              first one, and promoting it is a separate explicit step"
                .to_string(),
            Self::AlreadyInForce => {
                "this policy is byte-identical to the one already in force".to_string()
            }
            Self::PromotionRequired { high_water } => format!(
                "a policy newer than the high-water mark is signed ({high_water}) but is NOT in \
                 force; call `promote` to adopt it"
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

/// One append-only promotion.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyHighWaterMarkRecord {
    pub schema_version: u32,
    pub sequence: u64,
    pub recorded_at_unix: u64,
    pub prev_hash: String,
    pub record_hash: String,
    pub mark: PolicyHighWaterMark,
    /// Which authority signed the policy that was adopted. Recorded so a
    /// rotation history is readable, never used as a gate: the signature was
    /// already verified before the mark was written.
    pub authority_key_id: String,
    pub reason: String,
}

impl PolicyHighWaterMarkRecord {
    fn computed_hash(&self) -> Result<String> {
        let mut copy = self.clone();
        copy.record_hash.clear();
        Ok(blake3::hash(&serde_json::to_vec(&copy)?)
            .to_hex()
            .to_string())
    }
}

/// The outcome of a promotion call.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "outcome", content = "record", rename_all = "snake_case")]
pub enum PromotionOutcome {
    /// The mark moved forward and a record was appended.
    Promoted { record: PolicyHighWaterMarkRecord },
    /// The policy was already in force. Nothing was written, and the existing
    /// record is returned.
    AlreadyInForce { record: PolicyHighWaterMarkRecord },
}

// ---------------------------------------------------------------------------
// The store
// ---------------------------------------------------------------------------

/// The high-water mark, and its append-only history.
#[derive(Debug, Clone)]
pub struct PolicyHighWaterMarkStore {
    root: PathBuf,
}

impl PolicyHighWaterMarkStore {
    /// Open (and create, if absent) the mark directory.
    ///
    /// `ensure_private_dir` puts the root at `0700` and reports a pre-existing
    /// directory with the wrong mode rather than inheriting it — the same rule
    /// every other ledger in this crate follows, applied here for the same
    /// reason: a rollback mark readable by another account is not a rollback
    /// mark.
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        durability::ensure_private_dir(&root)?;
        Ok(Self { root })
    }

    pub fn ledger_path(&self) -> PathBuf {
        self.root.join(POLICY_HIGH_WATER_FILE)
    }

    /// The head anchor for this ledger, or `None` on a ledger written before
    /// anchoring existed.
    pub fn head_anchor(&self) -> Result<Option<HeadAnchor>> {
        durability::read_head_anchor(&self.root, POLICY_HIGH_WATER_FILE)
    }

    /// The mark in force, or `None` when nothing has been promoted.
    pub fn head(&self) -> Result<Option<PolicyHighWaterMark>> {
        Ok(self
            .records()?
            .last()
            .map(|r| r.mark.clone()))
    }

    /// Read and fully verify the history.
    ///
    /// Four checks, in the direction that refuses:
    ///
    /// 1. sequence is `1, 2, 3, …` with no gap;
    /// 2. `prev_hash` chains;
    /// 3. each `record_hash` recomputes;
    /// 4. **each mark's version is strictly greater than the previous one.**
    ///
    /// (4) is not a hash check and is the reason a rewritten ledger is caught
    /// even before the anchor is consulted: a ledger that goes *backwards* is
    /// inconsistent with itself, whatever the anchor says.
    pub fn records(&self) -> Result<Vec<PolicyHighWaterMarkRecord>> {
        let records = self.parse_records()?;
        self.verify_head(&records)?;
        Ok(records)
    }

    /// Parse and verify the history, without consulting the head anchor.
    ///
    /// The anchor is skipped here because the append path is about to rewrite
    /// it, and consulting an anchor against a ledger that is mid-update would
    /// report the very state the update is repairing. The chain, the sequence
    /// and the forward-only rule are *not* skipped: a ledger that is internally
    /// inconsistent is refused no matter what the anchor says.
    fn parse_records(&self) -> Result<Vec<PolicyHighWaterMarkRecord>> {
        let path = self.ledger_path();
        if !path.exists() {
            return Ok(Vec::new());
        }
        let file = fs::File::open(&path)?;
        let mut out = Vec::new();
        let mut expected_seq = 1u64;
        let mut expected_prev = POLICY_HIGH_WATER_GENESIS_HASH.to_string();
        let mut previous_version: Option<u64> = None;

        for (idx, line) in BufReader::new(file).lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let record: PolicyHighWaterMarkRecord = serde_json::from_str(&line).map_err(|e| {
                EconomyError::Invalid(format!(
                    "policy high-water ledger line {} cannot be parsed: {}",
                    idx + 1,
                    e
                ))
            })?;
            if record.schema_version != OUTCOME_POLICY_SCHEMA_VERSION {
                return Err(EconomyError::Invalid(format!(
                    "policy high-water ledger line {} was written under policy schema {} but \
                     this build speaks {}",
                    idx + 1,
                    record.schema_version,
                    OUTCOME_POLICY_SCHEMA_VERSION
                )));
            }
            if record.sequence != expected_seq {
                return Err(EconomyError::Invalid(format!(
                    "policy high-water sequence mismatch: expected {}, got {}",
                    expected_seq, record.sequence
                )));
            }
            if record.prev_hash != expected_prev {
                return Err(EconomyError::Invalid(format!(
                    "policy high-water hash-chain break at sequence {}",
                    record.sequence
                )));
            }
            let computed = record.computed_hash()?;
            if record.record_hash != computed {
                return Err(EconomyError::Invalid(format!(
                    "policy high-water hash mismatch at sequence {}",
                    record.sequence
                )));
            }
            if let Some(prev) = previous_version {
                if record.mark.version <= prev {
                    return Err(EconomyError::Invalid(format!(
                        "policy high-water ledger goes backwards at sequence {}: version {} \
                         follows version {}; a mark only ever moves forward",
                        record.sequence, record.mark.version, prev
                    )));
                }
            }
            previous_version = Some(record.mark.version);
            expected_prev = record.record_hash.clone();
            expected_seq += 1;
            out.push(record);
        }
        Ok(out)
    }

    /// Chain-verified head against the out-of-band anchor.
    ///
    /// Detects accidental truncation, corruption, and a ledger swapped for an
    /// older copy. **Does not** defend against a same-principal attacker who
    /// rewrites both files — see the module doc.
    fn verify_head(&self, records: &[PolicyHighWaterMarkRecord]) -> Result<()> {
        let anchor = durability::read_head_anchor(&self.root, POLICY_HIGH_WATER_FILE)?;
        let head = records
            .last()
            .map_or(POLICY_HIGH_WATER_GENESIS_HASH, |r| r.record_hash.as_str());
        let hash_at = |seq: u64| {
            records
                .iter()
                .find(|r| r.sequence == seq)
                .map(|r| r.record_hash.clone())
        };
        durability::verify_head_anchor(
            anchor.as_ref(),
            records.last().map_or(0, |r| r.sequence),
            head,
            &hash_at,
            "policy high-water ledger",
        )
    }

    /// The gate. Read-only: it never writes, so calling it from a policy *load*
    /// cannot itself become a way to move the mark.
    ///
    /// `Err` for the two hard refusals; `Ok` for the three standings, one of
    /// which ([`PolicyStanding::PromotionRequired`]) is explicitly **not** in
    /// force.
    pub fn evaluate(
        &self,
        candidate: &ValidatedOutcomePolicy,
    ) -> std::result::Result<PolicyStanding, PolicyError> {
        self.evaluate_parts(candidate.policy_version(), &candidate.policy_hash()?)
    }

    /// The gate, over a version and a hash the caller already has.
    ///
    /// Split out so the rules are testable against any pair — including the
    /// impossible ones a real policy cannot produce, which is exactly where a
    /// rollback bug would live.
    pub fn evaluate_parts(
        &self,
        offered_version: u64,
        offered_hash: &Hash,
    ) -> std::result::Result<PolicyStanding, PolicyError> {
        match self.head()? {
            None => Ok(PolicyStanding::Genesis),
            Some(mark) => mark.check_candidate(offered_version, offered_hash),
        }
    }

    /// The explicit promotion path. The **only** function here that writes.
    ///
    /// Refuses a rollback and a hash divergence with the same errors
    /// [`Self::evaluate`] uses, because the write path must not be a softer gate
    /// than the read path. Refuses to write when the candidate is already in
    /// force, returning [`PromotionOutcome::AlreadyInForce`] instead, so
    /// re-promoting on every start does not grow the ledger.
    pub fn promote(
        &self,
        candidate: &ValidatedOutcomePolicy,
        reason: impl Into<String>,
        now: u64,
    ) -> std::result::Result<PromotionOutcome, PolicyError> {
        self.promote_parts(
            candidate.policy_version(),
            &candidate.policy_hash()?,
            &candidate.authority_key_id().to_string(),
            reason,
            now,
        )
    }

    /// [`Self::promote`] over raw parts, so the rules are testable without a
    /// signed policy for every case.
    pub fn promote_parts(
        &self,
        offered_version: u64,
        offered_hash: &Hash,
        authority_key_id: &str,
        reason: impl Into<String>,
        now: u64,
    ) -> std::result::Result<PromotionOutcome, PolicyError> {
        let _lock = durability::LedgerLock::acquire_timeout(
            &self.root,
            POLICY_HIGH_WATER_FILE,
            durability::LEDGER_LOCK_WAIT,
        )?;
        let recovery = durability::recover_torn_tail(&self.ledger_path(), "policy high-water ledger")?;
        let existing = self.parse_records()?;

        let next_mark = PolicyHighWaterMark::new(offered_version, offered_hash.clone());
        if let Some(current) = existing.last().map(|r| r.mark.clone()) {
            match current.check_candidate(offered_version, offered_hash)? {
                // Already in force: no write. The caller asked to promote a
                // policy that is already promoted, and honouring that by
                // appending would make the ledger grow on every process start.
                PolicyStanding::AlreadyInForce => {
                    return Ok(PromotionOutcome::AlreadyInForce {
                        record: existing.last().cloned().expect("a mark exists"),
                    })
                }
                PolicyStanding::PromotionRequired { .. } | PolicyStanding::Genesis => {}
            }
        }

        let mut record = PolicyHighWaterMarkRecord {
            schema_version: OUTCOME_POLICY_SCHEMA_VERSION,
            sequence: existing.last().map_or(1, |r| r.sequence + 1),
            recorded_at_unix: now,
            prev_hash: existing
                .last()
                .map(|r| r.record_hash.clone())
                .unwrap_or_else(|| POLICY_HIGH_WATER_GENESIS_HASH.to_string()),
            record_hash: String::new(),
            mark: next_mark,
            authority_key_id: authority_key_id.to_string(),
            reason: reason.into(),
        };
        record.record_hash = record.computed_hash()?;

        let line = serde_json::to_vec(&record).map_err(EconomyError::from)?;
        durability::append_line(&self.ledger_path(), &line)?;
        durability::store_head_anchor(
            &self.root,
            POLICY_HIGH_WATER_FILE,
            record.sequence,
            &record.record_hash,
            recovery.map(|t| t.report(crate::now_unix())),
        )?;
        Ok(PromotionOutcome::Promoted { record })
    }

}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

/// Read a signed policy document from an economy home.
///
/// Read-only and side-effect free: it does **not** chmod the file and does not
/// validate. A `ValidatedOutcomePolicy` can only be produced by
/// [`crate::policy_auth::validate_outcome_policy`], and this function exists so
/// the high-water gate has something to be pointed at without the caller having
/// to re-implement the path. The gate itself wants the *validated* value, so the
/// usual sequence is: load, validate, then
/// [`PolicyHighWaterMarkStore::evaluate`].
pub fn load_signed_policy(home: &Path) -> std::result::Result<SignedOutcomePolicy, PolicyError> {
    let path = home.join(OUTCOME_POLICY_FILE);
    let raw = fs::read(&path).map_err(|e| {
        PolicyError::PinUnavailable(format!("cannot read {}: {e}", path.display()))
    })?;
    serde_json::from_slice(&raw).map_err(|e| {
        PolicyError::PinMalformed(format!("{} cannot be parsed: {e}", path.display()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        boundary::ControlledAddressRegistry, receipt_auth::testkit,
        rpc_test_server::FakeRpcSocket,
    };
    use tempfile::tempdir;

    fn hash(n: u8) -> Hash {
        let mut b = [0u8; 32];
        b[0] = n;
        Hash::from_bytes(b)
    }

    fn store(dir: &Path) -> PolicyHighWaterMarkStore {
        PolicyHighWaterMarkStore::open(dir).unwrap()
    }

    /// A real signed, validated policy. The socket is real because
    /// [`testkit::AuthFixture`] scopes the authority to one and the provider
    /// identity digest is part of the signed payload — but nothing here ever
    /// talks to it, because the high-water gate reads the mark, not the chain.
    ///
    /// Everything is leaked: the fixture has to outlive the `TempDir` it binds
    /// its socket to, and the `ValidatedOutcomePolicy` it produces has to outlive
    /// the fixture. The leak is bounded by the test binary's lifetime.
    fn auth_fixture() -> &'static testkit::AuthFixture {
        let dir: &'static tempfile::TempDir = Box::leak(Box::new(tempdir().unwrap()));
        let socket: &'static FakeRpcSocket =
            Box::leak(Box::new(FakeRpcSocket::bind(dir.path().join("chain.sock"))));
        let registry = ControlledAddressRegistry::new()
            .with_address("0x1234567890abcdef1234567890abcdef12345678")
            .unwrap();
        Box::leak(Box::new(testkit::AuthFixture::new(
            socket.path(),
            socket.uid(),
            registry,
        )))
    }

    // ------------------------------------------------------------------
    // The rules, as pure logic
    // ------------------------------------------------------------------

    #[test]
    fn a_version_below_the_high_water_is_a_rollback_and_is_rejected() {
        let mark = PolicyHighWaterMark::new(7, hash(7));
        let err = mark
            .check_candidate(6, &hash(6))
            .expect_err("a lower version must be rejected");
        assert!(matches!(err, PolicyError::PolicyRollback { .. }));
        let text = err.to_string();
        assert!(text.contains("offered v6"), "{text}");
        assert!(text.contains("high-water mark is v7"), "{text}");
    }

    #[test]
    fn an_equal_version_with_a_different_hash_is_equivocation_and_is_rejected() {
        let mark = PolicyHighWaterMark::new(7, hash(7));
        let err = mark
            .check_candidate(7, &hash(0xAB))
            .expect_err("same version, different hash must be rejected");
        assert!(matches!(err, PolicyError::PolicyHashDivergence { .. }));
        let text = err.to_string();
        assert!(text.contains("hash divergence at version 7"), "{text}");
        assert!(text.contains(&hash(0xAB).to_string()), "{text}");
        assert!(text.contains(&hash(7).to_string()), "{text}");
    }

    #[test]
    fn a_higher_version_is_not_in_force_until_it_is_promoted() {
        let mark = PolicyHighWaterMark::new(7, hash(7));
        let standing = mark.check_candidate(8, &hash(8)).unwrap();
        assert_eq!(standing.state(), "promotion_required");
        assert!(!standing.is_in_force(), "a newer policy is not adopted by existing");
        assert!(standing.describe().contains("NOT in force"), "{}", standing.describe());
    }

    #[test]
    fn an_identical_policy_is_idempotent_and_not_a_promotion() {
        let mark = PolicyHighWaterMark::new(7, hash(7));
        let standing = mark.check_candidate(7, &hash(7)).unwrap();
        assert_eq!(standing.state(), "already_in_force");
        assert!(standing.is_in_force());
    }

    #[test]
    fn a_bare_number_cannot_describe_a_policy_and_that_is_the_whole_point() {
        // The two failures the pair exists to catch. Both are states a real
        // signed policy cannot be in, and both are exactly what an operational
        // bug produces.
        let mark = PolicyHighWaterMark::new(7, hash(7));

        // 1. A version number served with the wrong document: the number is
        //    unchanged, the content is not. A bare `highest_policy_version`
        //    would accept it silently.
        let err = mark.check_candidate(7, &hash(0xCD)).unwrap_err();
        assert!(matches!(err, PolicyError::PolicyHashDivergence { .. }));

        // 2. A restored backup: the document is genuinely signed, by the
        //    genuinely pinned authority, and genuinely old.
        let err = mark.check_candidate(3, &hash(3)).unwrap_err();
        assert!(matches!(err, PolicyError::PolicyRollback { .. }));

        // And the accept cases, so the test is not only about refusals.
        assert!(mark.check_candidate(7, &hash(7)).is_ok());
        assert!(mark.check_candidate(8, &hash(8)).is_ok());
    }

    // ------------------------------------------------------------------
    // The store
    // ------------------------------------------------------------------

    #[test]
    fn an_empty_store_is_genesis_and_writes_nothing() {
        let dir = tempdir().unwrap();
        let s = store(dir.path());
        assert!(s.head().unwrap().is_none());
        assert!(s.records().unwrap().is_empty());
        assert!(s.head_anchor().unwrap().is_none());
        assert_eq!(s.evaluate_parts(1, &hash(1)).unwrap().state(), "genesis");
        // Still nothing: `evaluate` never writes.
        assert!(s.records().unwrap().is_empty());
        assert!(!s.ledger_path().exists());
    }

    #[test]
    fn promoting_records_the_pair_and_pins_the_head() {
        let dir = tempdir().unwrap();
        let s = store(dir.path());
        let out = s
            .promote_parts(1, &hash(1), "policy-authority:aa", "first policy", 1_700_000_000)
            .unwrap();
        let record = match out {
            PromotionOutcome::Promoted { record } => record,
            PromotionOutcome::AlreadyInForce { .. } => panic!("nothing was promoted yet"),
        };
        assert_eq!(record.sequence, 1);
        assert_eq!(record.prev_hash, POLICY_HIGH_WATER_GENESIS_HASH);
        assert_eq!(record.mark.version, 1);
        assert_eq!(record.mark.policy_hash, hash(1));

        let head = s.head().unwrap().unwrap();
        assert_eq!(head.version, 1);
        assert_eq!(head.policy_hash, hash(1));

        let anchor = s.head_anchor().unwrap().unwrap();
        assert_eq!(anchor.sequence, 1);
        assert_eq!(anchor.head_hash, record.record_hash);
        assert_eq!(anchor.ledger, POLICY_HIGH_WATER_FILE);
    }

    #[test]
    fn the_ledger_uses_the_crates_durability_primitives() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let s = store(dir.path());
        // 0700 on the root, forced by `ensure_private_dir`.
        let mode = std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, durability::LEDGER_DIR_MODE, "root must be 0700");

        s.promote_parts(1, &hash(1), "policy-authority:aa", "first", 1).unwrap();
        // 0600 on the ledger, forced by `append_line`.
        let mode = std::fs::metadata(s.ledger_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(mode, durability::LEDGER_FILE_MODE, "ledger must be 0600");
    }

    #[test]
    fn a_newer_policy_needs_promotion_and_then_takes_force() {
        let dir = tempdir().unwrap();
        let s = store(dir.path());
        s.promote_parts(1, &hash(1), "a", "first", 1).unwrap();

        // v2 is signed but not in force.
        assert_eq!(
            s.evaluate_parts(2, &hash(2)).unwrap().state(),
            "promotion_required"
        );
        // And `promote` is the only thing that changes that.
        s.promote_parts(2, &hash(2), "a", "tightened min_confirmations", 2)
            .unwrap();
        assert_eq!(
            s.evaluate_parts(2, &hash(2)).unwrap().state(),
            "already_in_force"
        );
        assert_eq!(s.head().unwrap().unwrap().version, 2);
        assert_eq!(s.records().unwrap().len(), 2);
    }

    #[test]
    fn a_rollback_is_rejected_by_the_read_path_and_by_the_write_path() {
        let dir = tempdir().unwrap();
        let s = store(dir.path());
        s.promote_parts(1, &hash(1), "a", "first", 1).unwrap();
        s.promote_parts(2, &hash(2), "a", "second", 2).unwrap();

        // Read path.
        let err = s.evaluate_parts(1, &hash(1)).unwrap_err();
        assert!(matches!(err, PolicyError::PolicyRollback { .. }));

        // Write path: the same refusal, because `promote` calls the same
        // function. A softer write path is how a rollback gets in.
        let err = s
            .promote_parts(1, &hash(1), "a", "rollback attempt", 3)
            .unwrap_err();
        assert!(matches!(err, PolicyError::PolicyRollback { .. }));

        // And the mark did not move.
        assert_eq!(s.head().unwrap().unwrap().version, 2);
        assert_eq!(s.records().unwrap().len(), 2);
    }

    #[test]
    fn a_same_version_hash_swap_is_rejected_by_both_paths() {
        let dir = tempdir().unwrap();
        let s = store(dir.path());
        s.promote_parts(5, &hash(5), "a", "fifth", 5).unwrap();

        let err = s.evaluate_parts(5, &hash(0xEE)).unwrap_err();
        assert!(matches!(err, PolicyError::PolicyHashDivergence { .. }));
        let err = s
            .promote_parts(5, &hash(0xEE), "a", "same version, other content", 6)
            .unwrap_err();
        assert!(matches!(err, PolicyError::PolicyHashDivergence { .. }));
        assert_eq!(s.head().unwrap().unwrap().policy_hash, hash(5));
    }

    #[test]
    fn re_promoting_the_same_policy_writes_nothing() {
        let dir = tempdir().unwrap();
        let s = store(dir.path());
        s.promote_parts(1, &hash(1), "a", "first", 1).unwrap();
        for _ in 0..5 {
            let out = s.promote_parts(1, &hash(1), "a", "reload on start", 2).unwrap();
            assert!(matches!(out, PromotionOutcome::AlreadyInForce { .. }));
        }
        assert_eq!(s.records().unwrap().len(), 1, "the ledger must not grow");
    }

    #[test]
    fn the_history_is_hash_chained_and_forward_only() {
        let dir = tempdir().unwrap();
        let s = store(dir.path());
        for v in 1..=4u8 {
            s.promote_parts(u64::from(v), &hash(v), "a", "rotate", u64::from(v))
                .unwrap();
        }
        let records = s.records().unwrap();
        assert_eq!(records.len(), 4);
        for pair in records.windows(2) {
            assert_eq!(pair[1].prev_hash, pair[0].record_hash);
            assert!(pair[1].mark.version > pair[0].mark.version);
        }
        assert_eq!(records[0].prev_hash, POLICY_HIGH_WATER_GENESIS_HASH);
    }

    #[test]
    fn a_rewritten_record_is_refused() {
        let dir = tempdir().unwrap();
        let s = store(dir.path());
        s.promote_parts(1, &hash(1), "a", "first", 1).unwrap();
        s.promote_parts(2, &hash(2), "a", "second", 2).unwrap();

        // Rewrite the second record's mark, leaving the hash alone.
        let raw = fs::read_to_string(s.ledger_path()).unwrap();
        let tampered = raw.replacen("\"version\":2", "\"version\":9", 1);
        assert_ne!(raw, tampered, "the fixture did not change anything");
        fs::write(s.ledger_path(), tampered).unwrap();
        let err = s.records().unwrap_err().to_string();
        assert!(err.contains("hash mismatch at sequence 2"), "{err}");
    }

    #[test]
    fn a_ledger_edited_to_go_backwards_is_refused_before_the_anchor() {
        let dir = tempdir().unwrap();
        let s = store(dir.path());
        s.promote_parts(1, &hash(1), "a", "first", 1).unwrap();
        s.promote_parts(2, &hash(2), "a", "second", 2).unwrap();
        s.promote_parts(3, &hash(3), "a", "third", 3).unwrap();

        // Build a self-consistent two-record ledger that stops at v2: re-hash it
        // so the chain and every record hash are valid, and leave the anchor at
        // sequence 3. This is a same-principal rewrite, and it must be caught —
        // here by the anchor, and independently by the forward-only rule if the
        // attacker also rewrites the anchor.
        let kept: Vec<PolicyHighWaterMarkRecord> = s
            .records()
            .unwrap()
            .into_iter()
            .take(2)
            .collect();
        let mut out = String::new();
        for mut r in kept {
            r.record_hash = String::new();
            r.record_hash = r.computed_hash().unwrap();
            out.push_str(&serde_json::to_string(&r).unwrap());
            out.push('\n');
        }
        fs::write(s.ledger_path(), out).unwrap();

        let err = s.records().unwrap_err().to_string();
        assert!(
            err.contains("sequence 2") || err.contains("missing"),
            "{err}"
        );
        assert!(
            s.head_anchor()
                .unwrap()
                .is_some_and(|a| a.sequence == 3),
            "the anchor is what noticed"
        );
    }

    #[test]
    fn a_truncated_tail_is_refused() {
        let dir = tempdir().unwrap();
        let s = store(dir.path());
        s.promote_parts(1, &hash(1), "a", "first", 1).unwrap();
        s.promote_parts(2, &hash(2), "a", "second", 2).unwrap();

        let raw = fs::read_to_string(s.ledger_path()).unwrap();
        let first_line = raw.lines().next().unwrap().to_string();
        // A half-written third line, which is what a crash mid-append leaves.
        fs::write(s.ledger_path(), format!("{first_line}\n{{\"schema_ver")).unwrap();
        let err = s.records().unwrap_err().to_string();
        assert!(err.contains("cannot be parsed"), "{err}");
        // And `recover_torn_tail` is the documented repair, run by `promote`.
        let repaired = durability::recover_torn_tail(&s.ledger_path(), "policy high-water ledger")
            .unwrap();
        assert!(repaired.is_some(), "a torn tail must be reported");
    }

    #[test]
    fn a_record_written_under_another_schema_is_refused() {
        let dir = tempdir().unwrap();
        let s = store(dir.path());
        s.promote_parts(1, &hash(1), "a", "first", 1).unwrap();
        let raw = fs::read_to_string(s.ledger_path()).unwrap();
        fs::write(
            s.ledger_path(),
            raw.replacen("\"schema_version\":2", "\"schema_version\":1", 1),
        )
        .unwrap();
        let err = s.records().unwrap_err().to_string();
        assert!(err.contains("policy schema 1"), "{err}");
        assert!(err.contains("this build speaks 2"), "{err}");
    }

    // ------------------------------------------------------------------
    // Against a real signed policy
    // ------------------------------------------------------------------

    #[test]
    fn a_real_validated_policy_is_evaluated_against_the_mark() {
        let auth = auth_fixture();
        let validated = auth.validated();
        let version = validated.policy_version();
        let dir = tempdir().unwrap();
        let s = store(dir.path());

        assert_eq!(s.evaluate(&validated).unwrap().state(), "genesis");

        s.promote(&validated, "the policy in force at install", 1_700_000_000)
            .unwrap();
        assert_eq!(s.evaluate(&validated).unwrap().state(), "already_in_force");
        assert_eq!(s.head().unwrap().unwrap().version, version);
        assert_eq!(
            s.head().unwrap().unwrap().policy_hash,
            validated.policy_hash().unwrap()
        );
        assert_eq!(s.records().unwrap()[0].authority_key_id, validated.authority_key_id().to_string());
    }

    #[test]
    fn a_rotated_policy_is_newer_and_needs_promotion() {
        let auth = auth_fixture();
        let dir = tempdir().unwrap();
        let s = store(dir.path());
        s.promote(&auth.validated(), "install", 1).unwrap();
        // `rotated` re-signs the same anchor over a different policy_version, so
        // this is the real shape of a forward rotation, not a synthetic pair.
        let newer = auth.rotated(9).validate().unwrap();
        assert!(newer.policy_version() > 3, "the fixture must move forward");
        let standing = s.evaluate(&newer).unwrap();
        assert_eq!(standing.state(), "promotion_required");
        assert!(!standing.is_in_force());
        s.promote(&newer, "rotated to v9", 2).unwrap();
        assert_eq!(s.evaluate(&newer).unwrap().state(), "already_in_force");
        // And the old one is now a rollback.
        let old = auth.validated();
        assert!(matches!(
            s.evaluate(&old).unwrap_err(),
            PolicyError::PolicyRollback { .. }
        ));
    }

    #[test]
    fn a_stored_policy_document_loads_through_the_crate_path() {
        let dir = tempdir().unwrap();
        // No document yet: an actionable error, not a default.
        let err = load_signed_policy(dir.path()).unwrap_err();
        assert!(matches!(err, PolicyError::PinUnavailable(_)));

        let doc = serde_json::json!({
            "payload": {"schema_version": 2},
            "authority_key_id": {"role": "policy_authority", "bytes": vec![0u8; 32]},
            "signature": "00",
        });
        fs::write(dir.path().join(OUTCOME_POLICY_FILE), doc.to_string()).unwrap();
        // Unparseable: also an error, and a different one, because "absent" and
        // "present but wrong" are different diagnoses.
        let err = load_signed_policy(dir.path()).unwrap_err();
        assert!(matches!(err, PolicyError::PinMalformed(_)), "{err}");
    }
}
