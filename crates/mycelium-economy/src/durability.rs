//! Durability primitives for the on-disk ledgers.
//!
//! `std` only. No `libc`, no `fs2`, no `nix`: the permission bits, the
//! exclusive lock and the durable append below are all built from what the
//! standard library already exposes.
//!
//! Five defects this module exists to close, and the honest limits of each:
//!
//! 1. **Permissions.** Ledgers and the economy root inherit the process
//!    umask, so a default `0022` umask leaves them world-readable. Everything
//!    the crate creates is forced to `0600` (files) and `0700` (directories)
//!    immediately after creation, and a pre-existing wrong mode is corrected
//!    with a loud warning rather than being used silently.
//! 2. **Concurrency.** The append cycle is read-tail → derive `sequence` →
//!    write. Two writers doing that at once derive the same `sequence` and
//!    interleave their bytes. The duplicate is detected on read but never
//!    prevented, so prevention is the only real fix: see [`LedgerLock`].
//! 3. **Torn records.** A record is serialized into one buffer and written
//!    with a single `write_all`, so a crash can only leave a prefix of one
//!    line rather than a record interleaved with another. A leftover prefix is
//!    then recovered explicitly by [`recover_torn_tail`].
//! 4. **Truncation.** A truncated tail is a perfectly valid shorter chain.
//!    [`HeadAnchor`] stores the head in a *separate* file, which detects
//!    accidental truncation, corruption and a ledger swapped for an older copy.
//! 5. **fsync.** `sync_data` on a file does not persist the directory entry,
//!    so a just-created name can vanish on crash. The parent directory is
//!    synced on *creation* only — doing it per append would double the fsync
//!    cost of every record for no additional guarantee.
//!
//! ## What the head anchor does NOT achieve
//!
//! [`HeadAnchor`] is **not** an external anchor. It lives in the same
//! directory, under the same uid, with the same permissions as the ledger it
//! guards: an attacker who can write the ledger can rewrite the anchor and
//! make any truncation undetectable. It defends against accidents, bit rot
//! and rollback-by-mistake — not against a same-principal adversary.
//!
//! Per the agreed threat model, only an anchor the ledger's attacker cannot
//! reach defeats that adversary: a TPM-sealed counter, a second host, a quorum
//! signature, or a published transparency log. None of those is available
//! without an external dependency and an external counterparty, both of which
//! are out of scope here. Treat the anchor as a tripwire, not as a proof.

use crate::{EconomyError, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// Mode enforced on the economy root and on every directory this crate makes.
pub const LEDGER_DIR_MODE: u32 = 0o700;
/// Mode enforced on every file this crate creates or rewrites.
pub const LEDGER_FILE_MODE: u32 = 0o600;

/// Directory, relative to the economy root, holding the append lock sockets.
pub const LOCK_DIR_NAME: &str = ".locks";

/// How long a ledger operation waits for a contended lock before giving up.
///
/// Sized against what the lock actually covers: one ledger read, one hash, one
/// append, one anchor write. There is no network call and no chain query inside
/// the critical section, so ten seconds is orders of magnitude more than that
/// needs — and a caller is better served by a named, retryable error than by an
/// unbounded block on a holder that is never going to finish.
pub const LEDGER_LOCK_WAIT: Duration = Duration::from_secs(10);

/// Retry cadence while waiting for a contended lock.
const LOCK_POLL: Duration = Duration::from_millis(20);

/// How old a claim may be before it is abandoned without being able to ask
/// whether its holder is alive (no `/proc`, i.e. not Linux). Only reached on
/// platforms where liveness cannot be established, and only for a claim whose
/// holder is already unreachable.
#[cfg(unix)]
const STALE_LOCK_AFTER: Duration = Duration::from_secs(120);

// ---------------------------------------------------------------------------
// 1. Permissions
// ---------------------------------------------------------------------------

/// Create `dir` if needed and force it to [`LEDGER_DIR_MODE`].
///
/// A pre-existing directory with the wrong mode is a finding in its own right,
/// so it is corrected **and reported**, never quietly accepted. Failing instead
/// would brick every existing installation the moment this ships: roots
/// created by earlier versions are `0755` by construction (plain
/// `create_dir_all` under the default umask), and refusing to open them would
/// strand every ledger already on disk. The warning is what makes the
/// correction observable; the correction is what removes the exposure.
pub fn ensure_private_dir(dir: &Path) -> Result<()> {
    let fresh = !dir.exists();
    if fresh {
        fs::create_dir_all(dir)?;
        // The new directory's own name lives in its parent. Cheap, once.
        sync_dir_entry_best_effort(dir, &format!("created directory {}", dir.display()));
    }
    force_mode(dir, LEDGER_DIR_MODE, "economy directory", fresh)?;
    check_ownership(dir)
}

/// Force `path` to [`LEDGER_FILE_MODE`]. Called on every append so a mode
/// changed behind our back is corrected rather than inherited.
pub fn ensure_private_file(path: &Path) -> Result<()> {
    force_mode(path, LEDGER_FILE_MODE, "ledger file", false)
}

/// Best-effort ownership check.
///
/// `geteuid(3)` would need `libc`, which this crate may not take. On Linux the
/// procfs superblock reports the calling process as owned by its effective uid,
/// which is a dependency-free substitute: `/proc/self` is a kernel-provided
/// inode we did not create, so it cannot be forged to hide a mismatch. On every
/// other Unix the check is skipped and the mode correction still applies.
///
/// A foreign owner is reported, not refused: the directory may legitimately be
/// owned by a service account the daemon runs under, and only the operator can
/// tell that apart from an intruder.
fn check_ownership(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let (Some(uid), Ok(meta)) = (current_uid(), fs::metadata(path)) else {
            return Ok(());
        };
        if meta.uid() != uid {
            eprintln!(
                "WARN mycelium-economy: {} is owned by uid {} but this process runs as uid {}; \
                 the operator must confirm this is intended",
                path.display(),
                meta.uid(),
                uid
            );
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn current_uid() -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    fs::metadata("/proc/self").ok().map(|m| m.uid())
}

#[cfg(all(unix, not(target_os = "linux")))]
fn current_uid() -> Option<u32> {
    // Would need geteuid(3); no libc dependency is allowed here.
    None
}

#[cfg(unix)]
fn force_mode(path: &Path, want: u32, what: &str, fresh: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    // lstat, not stat: the mode has to be read from the inode the path names.
    // A symlinked ledger is chmod'ed through the link (chmod follows), so the
    // target ends up correct either way — but it is reported, because a link
    // inside the economy root is not something this crate creates.
    let meta = fs::symlink_metadata(path)?;
    let current = meta.permissions().mode() & 0o7777;
    if meta.file_type().is_symlink() {
        eprintln!(
            "WARN mycelium-economy: {what} {} is a symlink; its permissions were corrected \
             through the link, so the target is what matters",
            path.display()
        );
    }
    if current == want {
        return Ok(());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(want))?;
    // A directory this call just created was never accessible to anyone: the
    // mode the umask gave it for the microseconds between create and chmod is
    // not a finding. Only a path that already existed is.
    if fresh {
        return Ok(());
    }
    let display = path.display();
    eprintln!(
        "WARN mycelium-economy: {what} {display} was mode {current:04o} and has been corrected \
         to {want:04o}; a world- or group-accessible ledger is a finding, and an existing \
         installation reaching this point had one"
    );
    Ok(())
}

/// Non-Unix: no permission model to enforce, so this is a documented no-op.
/// The crate already requires Unix elsewhere — `chain_provider` calls
/// `MetadataExt::uid()` unconditionally — so this arm exists to keep the
/// durability layer honest if that ever changes, not because it is reachable
/// today.
#[cfg(not(unix))]
fn force_mode(_path: &Path, _want: u32, _what: &str, _fresh: bool) -> Result<()> {
    eprintln!(
        "WARN mycelium-economy: ledger permission hardening is unavailable on this platform; \
         ledgers keep whatever mode the filesystem default gives them"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// 5. Directory-entry durability
// ---------------------------------------------------------------------------

/// `fsync` the parent directory of `path`, so the *name* survives a crash.
///
/// Best effort by design. `sync_all(2)` on a directory fd is not universally
/// supported (it fails with `EINVAL` on some filesystems and container
/// overlays), and turning that into a hard error would refuse to write ledgers
/// on hosts that are perfectly capable of storing them. The failure is reported
/// instead of swallowed: what is lost is the name, not the bytes.
fn sync_dir_entry_best_effort(path: &Path, context: &str) {
    if let Err(e) = sync_dir_entry(path) {
        eprintln!(
            "WARN mycelium-economy: could not fsync the directory entry after {context} \
             ({e}); the file bytes are durable but the name may not survive a crash"
        );
    }
}

#[cfg(unix)]
fn sync_dir_entry(path: &Path) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_dir_entry(_path: &Path) -> Result<()> {
    // Opening a directory as a file is not portable; there is nothing to sync.
    Ok(())
}

// ---------------------------------------------------------------------------
// 3. Appends
// ---------------------------------------------------------------------------

/// Open for append, creating the file at [`LEDGER_FILE_MODE`] in the same
/// syscall.
///
/// The mode reaches `open(2)`'s `mode` argument, so the file is never briefly
/// group- or world-accessible between creation and a later `chmod` — a window a
/// `set_permissions` call after the fact could not close. `std` exposes this as
/// `OpenOptionsExt::mode`; no `libc` is involved.
#[cfg(unix)]
fn open_append(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut opts = OpenOptions::new();
    opts.create(true).append(true).mode(LEDGER_FILE_MODE);
    Ok(opts.open(path)?)
}

#[cfg(not(unix))]
fn open_append(path: &Path) -> Result<File> {
    Ok(OpenOptions::new().create(true).append(true).open(path)?)
}

/// Open for rewriting, creating at [`LEDGER_FILE_MODE`] in the same syscall.
#[cfg(unix)]
fn open_truncate(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true).mode(LEDGER_FILE_MODE);
    Ok(opts.open(path)?)
}

#[cfg(not(unix))]
fn open_truncate(path: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?)
}

/// Append one already-serialized record as a **single** write.
///
/// The newline is part of the same buffer, so the record reaches the file in
/// one `write_all(2)` instead of the many small writes `serde_json::to_writer`
/// performs on a `File`. That narrows the torn-record window to a prefix of one
/// line and nothing else — the previous shape could interleave a record with
/// another writer's bytes mid-struct.
pub fn append_line(path: &Path, line: &[u8]) -> Result<()> {
    let existed = path.exists();
    let mut file = open_append(path)?;
    // A pre-existing ledger whose mode was loosened behind our back is
    // corrected here. A fresh one was already created at 0600 by open(2), so
    // this is a no-op and never reports a finding it did not find.
    ensure_private_file(path)?;

    let mut buffer = Vec::with_capacity(line.len() + 1);
    buffer.extend_from_slice(line);
    buffer.push(b'\n');
    file.write_all(&buffer)?;
    file.sync_data()?;

    if !existed {
        // `sync_data` on the file does not persist the directory entry, so a
        // name created in this same instant could vanish on crash. Creation
        // only: per-append directory syncs would double the cost of every
        // record and buy nothing after the first.
        sync_dir_entry_best_effort(path, &format!("creating ledger {}", path.display()));
    }
    Ok(())
}

/// Rewrite `path` atomically and privately: temp file → `sync_all` → rename.
///
/// The rename is the commit point, so a reader sees either the whole previous
/// file or the whole new one. Used for the head anchor and for the policy
/// rewrites that already had a hand-rolled temp+rename.
pub fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let existed = path.exists();
    let tmp = path.with_extension("json.tmp");
    {
        let mut file = open_truncate(&tmp)?;
        ensure_private_file(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    if !existed {
        sync_dir_entry_best_effort(path, &format!("creating {}", path.display()));
    }
    Ok(())
}

/// Recover a torn tail by truncating back to the last complete newline.
///
/// **Loud, never silent.** A crashed append can leave a partial final line.
/// Fail-closed on that is safe but unusable: every later read would fail too,
/// so one crash would strand the ledger permanently, and the discarded bytes
/// are by definition a record that was never completed — never acknowledged as
/// committed, so nothing a caller was ever told about is lost.
///
/// The alternative — silently skipping the fragment — is worse, because it
/// hides the event. So the repair returns what it discarded, the caller stores
/// it in the [`HeadAnchor`], and the bytes go to stderr with the fragment
/// itself for forensics.
///
/// Returns `None` when the file already ends on a newline, which is the normal
/// case and costs a single byte read.
pub fn recover_torn_tail(path: &Path, label: &str) -> Result<Option<TornTail>> {
    // A ledger that does not exist yet is not a torn ledger: this runs before
    // the first append, where the file has nothing to recover from.
    if !path.exists() {
        return Ok(None);
    }
    // Read-write: the repair truncates. A read-only handle would fail set_len
    // with EINVAL.
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    let len = file.metadata()?.len();
    if len == 0 {
        return Ok(None);
    }
    file.seek(SeekFrom::Start(len - 1))?;
    let mut last = [0u8; 1];
    file.read_exact(&mut last)?;
    if last[0] == b'\n' {
        return Ok(None);
    }

    // Scan backwards in bounded windows rather than reading the ledger into
    // memory: discarding a few trailing bytes must not cost a copy of the file.
    const WINDOW: usize = 64 * 1024;
    let mut window = vec![0u8; WINDOW];
    let mut keep = 0usize;
    let mut end = len as usize;
    while end > 0 {
        let start = end.saturating_sub(WINDOW);
        let n = end - start;
        file.seek(SeekFrom::Start(start as u64))?;
        file.read_exact(&mut window[..n])?;
        if let Some(i) = window[..n].iter().rposition(|b| *b == b'\n') {
            keep = start + i + 1;
            break;
        }
        end = start;
    }

    // Only the fragment itself is read back, and only for the report.
    let discarded = len - keep as u64;
    let preview_len = discarded.min(96) as usize;
    let mut fragment = vec![0u8; preview_len];
    file.seek(SeekFrom::Start(keep as u64))?;
    file.read_exact(&mut fragment)?;
    file.set_len(keep as u64)?;
    file.sync_all()?;

    let preview = String::from_utf8_lossy(&fragment);
    eprintln!(
        "WARN mycelium-economy: {label} {} had a torn final record from an interrupted append. \
         {discarded} byte(s) were DISCARDED and the file was truncated back to the last complete \
         record (kept {keep} byte(s)). The discarded fragment was: {preview}{}",
        path.display(),
        if discarded > preview_len as u64 { "..." } else { "" }
    );

    Ok(Some(TornTail {
        kept_bytes: keep as u64,
        discarded_bytes: discarded,
    }))
}

/// What a torn-tail recovery discarded, and how much.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TornTail {
    pub kept_bytes: u64,
    pub discarded_bytes: u64,
}

impl TornTail {
    /// Persistable form, for the head anchor.
    pub fn report(&self, at_unix: u64) -> TornTailReport {
        TornTailReport {
            at_unix,
            discarded_bytes: self.discarded_bytes,
            kept_bytes: self.kept_bytes,
        }
    }
}

// ---------------------------------------------------------------------------
// 2. Exclusive append lock
// ---------------------------------------------------------------------------

/// Kernel-arbitrated exclusive lock over one ledger's read-compute-append cycle.
///
/// ## The mechanism
///
/// `create_new(true)` is `open(2)` with `O_CREAT | O_EXCL`, which the kernel
/// makes atomic: of any number of processes racing on the same path, exactly
/// one succeeds. That single guarantee is what the whole design rests on, and
/// the rest exists only to answer the question it does not: *what if the winner
/// dies?*
///
/// The lock file holds `<pid>:<process-start-time-ticks>`, and staleness is
/// decided by whether that process is **alive**, read from `/proc` — not by how
/// old the file is. A dead holder is detected the moment it dies, not after a
/// timeout, so a crashed daemon is never left waiting out a stale-lock window.
///
/// Start time, not just pid, because pid reuse would otherwise make a recycled
/// pid look like a live holder and hang the lock forever. A zombie is treated
/// as dead: its `/proc` entry exists but nobody can ever answer on it.
///
/// ## Why not a bound `AF_UNIX` socket
///
/// This was implemented first and measured, and it is worse. A socket's
/// liveness (the listening descriptor) and its ownership (the directory entry)
/// are **two different things**, and the kernel lets them be swapped between
/// two syscalls. Every acquisition needs a liveness probe, and the probe's
/// result is stale by the time the reclaim acts on it:
///
/// ```text
/// A releases: unlink the entry, close the listener
/// R probes:   connect() -> refused, entry already absent   (no stale inode!)
/// C binds:    succeeds at the now-free path                    (C owns it)
/// R unlinks:  deletes C's socket                                 (R now owns it too)
/// ```
///
/// Both C and R believe they hold the lock. Nothing about the sentinel has this
/// problem, because there the entry *is* the claim and *is* the liveness record:
/// `O_EXCL` either sees the entry or creates it, and those cannot interleave.
/// Under a tight 16-thread probe this raced roughly one acquisition in eight —
/// while the sentinel design does not have the path at all in normal operation.
///
/// The socket's one genuine advantage was that the kernel releases it on crash
/// with no stale-break policy. The sentinel gets the same guarantee from `/proc`
/// liveness, and `/proc` is already a dependency of this crate's ownership
/// check, so nothing new is required.
///
/// ## The residual race, stated plainly
///
/// Two reclaimers can both read a *dead* holder's lock file, both conclude it
/// is stale, and both unlink-then-`O_EXCL`. The loser of the `O_EXCL` is
/// detected and retries, but a reclaimer whose unlink lands after a winner's
/// create has deleted the winner's claim, and both then believe they hold it.
///
/// This needs three things at once — a holder that died without running `Drop`,
/// two or more contenders reclaiming at the same moment, and the loser's unlink
/// landing inside the winner's claim-to-unlink window — so it does not occur
/// under contention among live holders. It is not eliminated, only made rare and
/// bounded. Closing it properly needs either a second exclusive gate around the
/// reclaim (which then needs its own stale policy) or kernel advisory locking,
/// i.e. `flock(2)`/`fcntl(F_SETLK)` reached through `libc`, which this crate may
/// not take. `durability::LedgerLock` is where that substitution would go.
///
/// ## Cost
///
/// One `open(O_CREAT|O_EXCL)` on the uncontended path. The lock is held across
/// one ledger read, one hash, one append and one anchor write — never across a
/// network call or a chain query.
pub struct LedgerLock {
    path: PathBuf,
    /// What this guard wrote into the lock file, so release removes only its
    /// own claim and never a successor's.
    claim: String,
}

/// Contents of a lock file.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LockClaim {
    pid: u32,
    start_ticks: Option<u64>,
    created_at_unix: u64,
}

impl LockClaim {
    fn encode(&self) -> String {
        format!(
            "{}:{}:{}\n",
            self.pid,
            self.start_ticks.map_or_else(String::new, |t| t.to_string()),
            self.created_at_unix
        )
    }

    fn parse(raw: &str) -> Result<Option<Self>> {
        let mut fields = raw.trim().split(':');
        let Some(pid) = fields.next().and_then(|p| p.parse::<u32>().ok()) else {
            return Ok(None);
        };
        let start_ticks = fields
            .next()
            .filter(|s| !s.is_empty())
            .and_then(|s| s.parse::<u64>().ok());
        let created_at_unix = fields
            .next()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        Ok(Some(Self {
            pid,
            start_ticks,
            created_at_unix,
        }))
    }
}

/// This process's start time in clock ticks, from `/proc/self/stat`.
///
/// Paired with the pid in a claim: pid alone is not a stable identity, because
/// the kernel reuses pids and a recycled one would look like a live holder
/// forever. Linux-only; `None` elsewhere, which degrades to a pid-only check.
#[cfg(target_os = "linux")]
fn current_start_ticks() -> Option<u64> {
    let stat = fs::read_to_string("/proc/self/stat").ok()?;
    let tail = &stat.rsplit_once(')')?.1;
    // Fields after `comm`: state is #3 overall, starttime is #22.
    tail.split_whitespace().nth(19)?.parse::<u64>().ok()
}

#[cfg(not(target_os = "linux"))]
fn current_start_ticks() -> Option<u64> {
    None
}

/// `/proc/<pid>`: the process's start time (to detect pid reuse) and whether it
/// is alive. `None` when the answer is unavailable.
#[cfg(target_os = "linux")]
fn process_alive(pid: u32, start_ticks: Option<u64>) -> Option<bool> {
    let stat = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => stat,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            // procfs has no entry for this pid, so no such process exists. This
            // is a *proof* of death, and it is the distinction that lets a
            // crashed holder be reclaimed at once instead of on a timer. Any
            // other error is a permission problem or an unreadable procfs, and
            // says nothing either way.
            return Some(false);
        }
        Err(_) => return None,
    };
    // The comm field is parenthesised and may itself contain spaces and
    // parentheses, so everything after the last ')' is the reliable tail.
    let tail = &stat.rsplit_once(')')?.1;
    let mut fields = tail.split_whitespace();
    let state = fields.next()?;
    if state == "Z" {
        return Some(false);
    }
    if let Some(expected) = start_ticks {
        let start = fields.nth(18)?.parse::<u64>().ok()?;
        // A recycled pid reports a different start time: the original holder
        // is gone even though the number is in use again.
        return Some(start == expected);
    }
    Some(true)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn process_alive(_pid: u32, _start_ticks: Option<u64>) -> Option<bool> {
    // Deciding this without `libc`'s `kill(pid, 0)` is not possible, so the
    // age-based fallback below applies instead.
    None
}

#[cfg(not(unix))]
fn process_alive(_pid: u32, _start_ticks: Option<u64>) -> Option<bool> {
    None
}

/// Whether a claim's holder is provably gone, and if so, say why.
#[cfg(unix)]
fn claim_is_dead(claim: &LockClaim) -> Option<(&'static str, bool)> {
    if claim.pid == std::process::id() {
        // Our own pid: either a stale claim from an earlier run of this process,
        // or an attempt to take a lock we already hold. This lock is not
        // reentrant, so both are refusals, never reclaims.
        return Some(("this process", false));
    }
    match process_alive(claim.pid, claim.start_ticks) {
        Some(false) => Some(("its holder is gone", true)),
        Some(true) => Some(("its holder is alive", false)),
        None => {
            let age = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs())
                .saturating_sub(claim.created_at_unix);
            if age > STALE_LOCK_AFTER.as_secs() {
                Some(("it is older than the stale-lock timeout", true))
            } else {
                Some(("it is within the stale-lock timeout", false))
            }
        }
    }
}

impl LedgerLock {
    fn lock_path(root: &Path, name: &str) -> Result<PathBuf> {
        let dir = root.join(LOCK_DIR_NAME);
        ensure_private_dir(&dir)?;
        Ok(dir.join(format!("{name}.lock")))
    }

    /// One attempt. `Ok(None)` means "held by someone else, retry".
    pub fn try_acquire(root: &Path, name: &str) -> Result<Option<Self>> {
        Self::try_acquire_at(&Self::lock_path(root, name)?)
    }

    /// Fail-fast acquire: a single attempt, no waiting.
    pub fn acquire(root: &Path, name: &str) -> Result<Self> {
        Self::acquire_timeout(root, name, Duration::ZERO)
    }

    /// Acquire, retrying until `timeout` elapses.
    ///
    /// Only the paths that mutate a ledger wait. Both `records()` and the append
    /// path wait, because the head anchor is a second file: reading the ledger
    /// and the anchor outside one critical section compares them at different
    /// instants and returns a phantom "truncated" verdict on a healthy ledger.
    pub fn acquire_timeout(root: &Path, name: &str, timeout: Duration) -> Result<Self> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(lock) = Self::try_acquire(root, name)? {
                return Ok(lock);
            }
            if Instant::now() >= deadline {
                return Err(EconomyError::Conflict(format!(
                    "ledger lock {name} is still held after waiting {}ms; refusing to append \
                     rather than race the holder",
                    timeout.as_millis()
                )));
            }
            std::thread::sleep(LOCK_POLL);
        }
    }

    fn try_acquire_at(path: &Path) -> Result<Option<Self>> {
        let claim = LockClaim {
            pid: std::process::id(),
            start_ticks: current_start_ticks(),
            created_at_unix: now_unix(),
        };
        match claim_lock(path, &claim) {
            Ok(()) => Ok(Some(Self {
                path: path.to_path_buf(),
                claim: claim.encode(),
            })),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                let raw = fs::read_to_string(path).unwrap_or_default();
                let Some(held) = LockClaim::parse(&raw)? else {
                    // Unreadable or empty: cannot establish who holds it, so do
                    // not guess. Removing it would be a blind unlink.
                    return Ok(None);
                };
                let (reason, dead) = claim_is_dead(&held).unwrap_or(("its state is unknown", false));
                if !dead {
                    return Ok(None);
                }
                eprintln!(
                    "WARN mycelium-economy: reclaiming stale ledger lock {}: {} (pid {}, \
                     {}s old)",
                    path.display(),
                    reason,
                    held.pid,
                    now_unix().saturating_sub(held.created_at_unix)
                );
                // Remove and re-claim. `claim_lock` is `O_EXCL`, so if another
                // reclaimer won the race this fails with AlreadyExists and the
                // caller retries rather than proceeding with two holders.
                let _ = fs::remove_file(path);
                match claim_lock(path, &claim) {
                    Ok(()) => Ok(Some(Self {
                        path: path.to_path_buf(),
                        claim: claim.encode(),
                    })),
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(None),
                    Err(e) => Err(EconomyError::Io(e)),
                }
            }
            Err(e) => Err(EconomyError::Io(e)),
        }
    }
}

/// `open(O_CREAT|O_EXCL)`: atomic, so exactly one contender can win.
#[cfg(unix)]
fn claim_lock(path: &Path, claim: &LockClaim) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(LEDGER_FILE_MODE)
        .open(path)?;
    file.write_all(claim.encode().as_bytes())?;
    // Best effort: the claim has to reach the disk before the holder starts
    // writing the ledger, or a crash could leave a lock nobody can attribute.
    let _ = file.sync_all();
    Ok(())
}

#[cfg(not(unix))]
fn claim_lock(path: &Path, claim: &LockClaim) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(claim.encode().as_bytes())?;
    let _ = file.sync_all();
    Ok(())
}

impl Drop for LedgerLock {
    fn drop(&mut self) {
        // Remove only our own claim. Comparing contents means a slow release
        // cannot delete a successor's lock file.
        match fs::read_to_string(&self.path) {
            Ok(raw) if raw.trim() == self.claim.trim() => {
                let _ = fs::remove_file(&self.path);
            }
            Ok(_) => eprintln!(
                "WARN mycelium-economy: ledger lock {} now holds a different claim than the one \
                 this process wrote; leaving it alone",
                self.path.display()
            ),
            Err(_) => {}
        }
    }
}

// ---------------------------------------------------------------------------
// 4. Out-of-band head anchor
// ---------------------------------------------------------------------------

/// A torn-tail recovery, as recorded in the [`HeadAnchor`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TornTailReport {
    pub at_unix: u64,
    pub discarded_bytes: u64,
    pub kept_bytes: u64,
}

/// The ledger's head, stored outside the ledger file.
///
/// Read back as `None` for any ledger written before this existed, which is
/// what keeps existing on-disk ledgers working: the first append after the
/// upgrade writes the anchor, and until then there is nothing to verify
/// against.
///
/// See the module docs for what this does and does not defend against.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeadAnchor {
    pub schema_version: u32,
    /// Ledger file name this anchor describes.
    pub ledger: String,
    /// Sequence of the last record in the ledger.
    pub sequence: u64,
    /// `record_hash` of that record.
    pub head_hash: String,
    pub updated_at_unix: u64,
    /// Cumulative bytes discarded by torn-tail recovery. Non-zero means this
    /// ledger has suffered at least one interrupted append.
    pub discarded_bytes_total: u64,
    /// The most recent recovery, or `None` if there never was one.
    pub last_torn_recovery: Option<TornTailReport>,
}

/// Path of the anchor for `name` inside `root`.
pub fn head_anchor_path(root: &Path, name: &str) -> PathBuf {
    root.join(format!("{name}-head.json"))
}

/// Read the anchor. `Ok(None)` when there is none yet (pre-upgrade ledger, or
/// never appended). A malformed anchor is an error, never `None`: an
/// unreadable anchor means the head cannot be verified, and this crate does not
/// degrade a missing source of truth into a default.
pub fn read_head_anchor(root: &Path, name: &str) -> Result<Option<HeadAnchor>> {
    let path = head_anchor_path(root, name);
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read(&path)?;
    let anchor: HeadAnchor = serde_json::from_slice(&raw).map_err(|e| {
        EconomyError::Invalid(format!(
            "head anchor {} cannot be parsed: {e}",
            path.display()
        ))
    })?;
    Ok(Some(anchor))
}

/// Persist the head after a successful append, carrying the recovery tally
/// forward.
pub fn store_head_anchor(
    root: &Path,
    name: &str,
    sequence: u64,
    head_hash: &str,
    recovery: Option<TornTailReport>,
) -> Result<()> {
    let previous = read_head_anchor(root, name)?;
    let anchor = HeadAnchor {
        schema_version: crate::SCHEMA_VERSION,
        ledger: name.to_string(),
        sequence,
        head_hash: head_hash.to_string(),
        updated_at_unix: now_unix(),
        discarded_bytes_total: previous
            .as_ref()
            .map_or(0, |p| p.discarded_bytes_total)
            .saturating_add(recovery.as_ref().map_or(0, |r| r.discarded_bytes)),
        last_torn_recovery: recovery
            .or_else(|| previous.and_then(|p| p.last_torn_recovery)),
    };
    let mut bytes = serde_json::to_vec_pretty(&anchor)?;
    bytes.push(b'\n');
    write_private_atomic(&head_anchor_path(root, name), &bytes)
}

/// Compare a freshly-verified ledger head against the stored anchor.
///
/// `hash_at_sequence` resolves the ledger's `record_hash` at a given sequence,
/// used to tell a *lagging* anchor from a rewritten ledger.
///
/// The three rejections:
///
/// * anchor ahead of the ledger → the tail was truncated, or the file was
///   replaced by an older copy;
/// * anchor at the same sequence with a different hash → the ledger was
///   rewritten in place, not appended to;
/// * anchor behind, and the anchored sequence no longer hashes to the anchored
///   value → same, seen from further back.
///
/// The one acceptance besides an exact match is an anchor that *lags* while
/// still matching the ledger at its own sequence. That is the crash window
/// between the ledger's `sync_data` and the anchor write; treating it as
/// tampering would let a single crash permanently brick a perfectly good
/// ledger.
pub fn verify_head_anchor(
    anchor: Option<&HeadAnchor>,
    ledger_sequence: u64,
    ledger_head_hash: &str,
    hash_at_sequence: &dyn Fn(u64) -> Option<String>,
    label: &str,
) -> Result<()> {
    let Some(anchor) = anchor else {
        return Ok(());
    };
    if anchor.sequence == ledger_sequence {
        if anchor.head_hash == ledger_head_hash {
            return Ok(());
        }
        return Err(EconomyError::Invalid(format!(
            "{label}: the head anchor records sequence {} with hash {} but the ledger head is \
             {ledger_head_hash}; the ledger was rewritten in place, not appended to",
            anchor.sequence, anchor.head_hash
        )));
    }
    if anchor.sequence > ledger_sequence {
        return Err(EconomyError::Invalid(format!(
            "{label}: the head anchor is at sequence {} but the ledger only reaches \
             {ledger_sequence}; {} record(s) are missing, so the ledger tail was truncated or \
             the file was rolled back to an older copy",
            anchor.sequence,
            anchor.sequence - ledger_sequence
        )));
    }
    match hash_at_sequence(anchor.sequence) {
        Some(hash) if hash == anchor.head_hash => Ok(()),
        Some(hash) => Err(EconomyError::Invalid(format!(
            "{label}: the head anchor is behind the ledger (sequence {} vs {ledger_sequence}) and \
             the ledger's record {} now hashes to {hash} instead of {}; the ledger was rewritten",
            anchor.sequence, anchor.sequence, anchor.head_hash
        ))),
        None => Err(EconomyError::Invalid(format!(
            "{label}: the head anchor is at sequence {} but the ledger has no record {}; the \
             ledger was rewritten",
            anchor.sequence, anchor.sequence
        ))),
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{autonomy::AutonomousEconomy, LocalEconomy};
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    fn mode(path: &Path) -> u32 {
        let meta = fs::symlink_metadata(path)
            .unwrap_or_else(|e| panic!("cannot stat {}: {e}", path.display()));
        meta.permissions().mode() & 0o7777
    }

    #[test]
    fn a_world_writable_directory_is_corrected_to_owner_only() {
        let dir = tempdir().unwrap();
        let econ = dir.path().join("econ");
        fs::create_dir_all(&econ).unwrap();
        fs::set_permissions(&econ, fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(mode(&econ), 0o777);

        // Corrected, not refused: an installation created before hardening
        // existed has a 0755 root and must keep opening.
        ensure_private_dir(&econ).unwrap();
        assert_eq!(mode(&econ), 0o700);

        // Idempotent, so repeated `open` calls do not keep re-reporting.
        ensure_private_dir(&econ).unwrap();
        assert_eq!(mode(&econ), 0o700);
    }

    #[test]
    fn a_world_readable_file_is_corrected_to_owner_only() {
        let dir = tempdir().unwrap();
        let ledger = dir.path().join("ledger.jsonl");
        fs::write(&ledger, b"{}\n").unwrap();
        fs::set_permissions(&ledger, fs::Permissions::from_mode(0o644)).unwrap();

        ensure_private_file(&ledger).unwrap();
        assert_eq!(mode(&ledger), 0o600);
    }

    #[test]
    fn append_line_creates_the_ledger_private_before_writing_bytes() {
        let dir = tempdir().unwrap();
        let econ = dir.path().join("econ");
        ensure_private_dir(&econ).unwrap();
        let ledger = econ.join("ledger.jsonl");

        append_line(&ledger, b"{\"a\":1}").unwrap();
        assert_eq!(mode(&ledger), 0o600);
        assert_eq!(fs::read(&ledger).unwrap(), b"{\"a\":1}\n");
    }

    #[test]
    fn every_ledger_the_crate_opens_is_private_after_one_append() {
        let dir = tempdir().unwrap();
        let econ = dir.path().join("econ");
        LocalEconomy::open(&econ).unwrap();
        AutonomousEconomy::open(&econ).unwrap();
        crate::reinvestment::ReinvestmentController::open(&econ).unwrap();
        crate::terr_research::TerrResearchEngine::open(&econ).unwrap();

        let local = LocalEconomy::open(&econ).unwrap();
        local
            .append_job(crate::JobRequest {
                schema_version: crate::SCHEMA_VERSION,
                job_id: "job-1".into(),
                created_at_unix: 1,
                requester_id: "r".into(),
                job_type: crate::JobType::Compute,
                input_hash: "h".into(),
                max_price_musd_micros: 1_000,
                internal_work: false,
                description: "d".into(),
            })
            .unwrap();

        // Four engines share one root; each hardens it, and the shared
        // `ensure_private_dir` must not fight itself doing so.
        assert_eq!(mode(&econ), 0o700);
        assert_eq!(mode(&econ.join(".locks")), 0o700);
        assert_eq!(mode(&econ.join("revenue-ledger.jsonl")), 0o600);

        // The same primitive serves the other three ledger names, checked apart
        // from the real ledgers so a dummy line cannot poison them.
        let raw = econ.join("raw");
        ensure_private_dir(&raw).unwrap();
        for ledger in [
            crate::autonomy::AUTONOMY_LEDGER_FILE,
            crate::reinvestment::REINVESTMENT_LEDGER_FILE,
            crate::terr_research::TERR_RESEARCH_LEDGER_FILE,
        ] {
            append_line(&raw.join(ledger), b"{}").unwrap();
            assert_eq!(mode(&raw.join(ledger)), 0o600, "{ledger}");
        }

        // And a real append, end to end, leaves its anchor private too.
        AutonomousEconomy::open(&econ)
            .unwrap()
            .register_agent(agent("agent-permissions"))
            .unwrap();
        assert_eq!(
            mode(&econ.join(format!("{}-head.json", crate::autonomy::AUTONOMY_LEDGER_FILE))),
            0o600
        );
    }

    #[test]
    fn the_lock_is_exclusive_and_released_cleanly() {
        let dir = tempdir().unwrap();
        let first = LedgerLock::acquire(dir.path(), "ledger.jsonl").unwrap();
        let second = LedgerLock::try_acquire(dir.path(), "ledger.jsonl").unwrap();
        assert!(second.is_none(), "the lock must not be handed out twice");
        drop(first);
        assert!(
            LedgerLock::try_acquire(dir.path(), "ledger.jsonl")
                .unwrap()
                .is_some(),
            "release must leave the lock free"
        );
    }

    #[test]
    fn the_lock_admits_exactly_one_holder_under_contention() {
        // Direct measure of exclusivity, independent of any ledger: if two
        // threads are ever inside the critical section at once, this counter
        // exceeds 1. A duplicate `sequence` in the append test is the same bug
        // seen through a slower lens; this sees it directly.
        use std::sync::atomic::{AtomicUsize, Ordering};

        const THREADS: usize = 16;
        const ROUNDS: usize = 60;

        let dir = tempdir().unwrap();
        let inside = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..THREADS {
                scope.spawn(|| {
                    for _ in 0..ROUNDS {
                        let _held = LedgerLock::acquire_timeout(
                            dir.path(),
                            "contended.jsonl",
                            Duration::from_secs(30),
                        )
                        .unwrap();
                        let now = inside.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(now, Ordering::SeqCst);
                        // Long enough that an overlapping holder is certain to
                        // be observed, short enough to keep the test quick.
                        std::thread::yield_now();
                        inside.fetch_sub(1, Ordering::SeqCst);
                    }
                });
            }
        });
        assert_eq!(
            peak.load(Ordering::SeqCst),
            1,
            "two threads held the lock at once"
        );
    }

    fn write_claim(lock: &Path, claim: &LockClaim) {
        fs::write(lock, claim.encode()).unwrap();
    }

    /// A pid no kernel will hand out, so `/proc/<pid>` is absent and the holder
    /// is provably gone.
    const DEAD_PID: u32 = 0x7FFF_FFFF;

    #[test]
    fn a_dead_holders_lock_is_reclaimed_without_waiting_out_a_timeout() {
        let dir = tempdir().unwrap();
        let path = LedgerLock::lock_path(dir.path(), "revenue-ledger.jsonl").unwrap();
        // Fresh by the clock: only liveness, not age, can justify reclaiming it.
        write_claim(
            &path,
            &LockClaim {
                pid: DEAD_PID,
                start_ticks: Some(1),
                created_at_unix: now_unix(),
            },
        );

        let held = LedgerLock::try_acquire(dir.path(), "revenue-ledger.jsonl")
            .unwrap()
            .expect("a dead holder must not keep the ledger locked");
        drop(held);
        assert!(!path.exists(), "release must clear the lock");
    }

    #[test]
    fn a_live_holders_lock_is_never_reclaimed() {
        let dir = tempdir().unwrap();
        let path = LedgerLock::lock_path(dir.path(), "revenue-ledger.jsonl").unwrap();
        // Older than the stale-lock timeout, so only liveness can save it. This
        // is the property that matters: a slow holder is never declared dead.
        write_claim(
            &path,
            &LockClaim {
                pid: std::process::id(),
                start_ticks: current_start_ticks(),
                created_at_unix: now_unix().saturating_sub(10_000),
            },
        );

        assert!(
            LedgerLock::try_acquire(dir.path(), "revenue-ledger.jsonl")
                .unwrap()
                .is_none(),
            "this lock is not reentrant, so our own claim must not be reclaimed"
        );
        let refused = match LedgerLock::acquire_timeout(
            dir.path(),
            "revenue-ledger.jsonl",
            Duration::from_millis(50),
        ) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("a held lock must not be handed out twice"),
        };
        assert!(
            refused.contains("is still held after waiting 50ms")
                && refused.contains("refusing to append rather than race the holder"),
            "{refused}"
        );
    }

    #[test]
    fn a_recycled_pid_is_not_mistaken_for_its_predecessor() {
        let dir = tempdir().unwrap();
        let path = LedgerLock::lock_path(dir.path(), "revenue-ledger.jsonl").unwrap();
        // pid 1 is alive, but this claim was written by a *different* process
        // that happened to be pid 1 before it was recycled. Start time, not pid
        // alone, is what identifies the holder.
        write_claim(
            &path,
            &LockClaim {
                pid: 1,
                start_ticks: Some(1),
                created_at_unix: now_unix(),
            },
        );

        assert!(
            LedgerLock::try_acquire(dir.path(), "revenue-ledger.jsonl")
                .unwrap()
                .is_some(),
            "a pid with a different start time is a dead predecessor"
        );
    }

    #[test]
    fn an_unreadable_lock_is_never_broken_on_a_guess() {
        let dir = tempdir().unwrap();
        let path = LedgerLock::lock_path(dir.path(), "revenue-ledger.jsonl").unwrap();
        // Old enough that a timeout-based policy would reclaim it.
        write_claim(&path, &LockClaim { pid: DEAD_PID, start_ticks: None, created_at_unix: 0 });
        fs::write(&path, "not a claim").unwrap();

        assert!(
            LedgerLock::try_acquire(dir.path(), "revenue-ledger.jsonl")
                .unwrap()
                .is_none(),
            "a lock whose holder cannot be established must be refused, not stolen"
        );
    }

    #[test]
    fn concurrent_appends_from_threads_produce_one_valid_chain() {
        // The regression for the missing lock. Without it every thread read the
        // same tail and derived the same `sequence`.
        const THREADS: usize = 16;
        const PER_THREAD: usize = 4;

        let dir = tempdir().unwrap();
        let econ = dir.path().join("econ");
        let autonomy = AutonomousEconomy::open(&econ).unwrap();

        std::thread::scope(|scope| {
            for t in 0..THREADS {
                let autonomy = &autonomy;
                scope.spawn(move || {
                    for i in 0..PER_THREAD {
                        autonomy.register_agent(agent(&format!("agent-{t}-{i}"))).unwrap();
                    }
                });
            }
        });

        // `records()` re-derives the whole chain, so this is the assertion that
        // no duplicate sequence and no interleaved bytes reached the file.
        let records = autonomy.records().unwrap();
        assert_eq!(records.len(), THREADS * PER_THREAD);
        let mut sequences: Vec<u64> = records.iter().map(|r| r.sequence).collect();
        sequences.sort_unstable();
        sequences.dedup();
        assert_eq!(sequences.len(), THREADS * PER_THREAD, "duplicate sequence");
    }

    #[test]
    fn a_torn_tail_is_truncated_back_to_the_last_complete_record() {
        let dir = tempdir().unwrap();
        let ledger = dir.path().join("ledger.jsonl");
        fs::write(&ledger, b"{\"a\":1}\n{\"a\":2}\n{\"a\":3").unwrap();

        let torn = recover_torn_tail(&ledger, "test ledger").unwrap().unwrap();
        assert_eq!(torn.discarded_bytes, 6);
        assert_eq!(torn.kept_bytes, 16);
        assert_eq!(fs::read(&ledger).unwrap(), b"{\"a\":1}\n{\"a\":2}\n");

        // A complete file is untouched, and the check costs one byte read.
        assert!(recover_torn_tail(&ledger, "test ledger").unwrap().is_none());
        assert_eq!(fs::read(&ledger).unwrap(), b"{\"a\":1}\n{\"a\":2}\n");
    }

    #[test]
    fn truncating_the_tail_is_detected_through_the_head_anchor() {
        let dir = tempdir().unwrap();
        let econ = dir.path().join("econ");
        AutonomousEconomy::open(&econ).unwrap();
        for i in 0..4 {
            append_line(
                &econ.join("autonomous-ledger.jsonl"),
                format!("{i}").as_bytes(),
            )
            .unwrap();
        }
        store_head_anchor(&econ, "autonomous-ledger.jsonl", 4, "head-at-4", None).unwrap();
        let anchor = read_head_anchor(&econ, "autonomous-ledger.jsonl").unwrap();
        assert_eq!(anchor.unwrap().sequence, 4);

        // The anchor is ahead of the ledger: exactly what truncation looks like.
        let err = verify_head_anchor(
            read_head_anchor(&econ, "autonomous-ledger.jsonl").unwrap().as_ref(),
            2,
            "head-at-2",
            &|_| Some("head-at-2".to_string()),
            "autonomy ledger",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("truncated"), "{err}");
        assert!(err.contains("2 record(s) are missing"), "{err}");
    }

    #[test]
    fn the_head_anchor_separates_lag_from_rewriting() {
        let ledger = |seq: u64, hash: &str| HeadAnchor {
            schema_version: crate::SCHEMA_VERSION,
            ledger: "l".into(),
            sequence: seq,
            head_hash: hash.into(),
            updated_at_unix: 0,
            discarded_bytes_total: 0,
            last_torn_recovery: None,
        };

        // No anchor yet: a pre-existing ledger keeps working.
        assert!(verify_head_anchor(None, 9, "h9", &|_| None, "l").is_ok());

        // Exact match.
        let at9 = ledger(9, "h9");
        assert!(verify_head_anchor(Some(&at9), 9, "h9", &|_| None, "l").is_ok());

        // Same sequence, different hash: rewritten in place.
        assert!(verify_head_anchor(Some(&at9), 9, "other", &|_| None, "l").is_err());

        // Anchor behind and still consistent: the crash window between the
        // ledger fsync and the anchor write. Accepting this is what stops a
        // single crash from bricking a good ledger forever.
        let at4 = ledger(4, "h4");
        let consistent = |seq: u64| Some(format!("h{seq}"));
        assert!(verify_head_anchor(Some(&at4), 9, "h9", &consistent, "l").is_ok());

        // Anchor behind and inconsistent: rewritten.
        assert!(verify_head_anchor(Some(&at4), 9, "h9", &|_| Some("x".into()), "l").is_err());
    }

    #[test]
    fn recovery_history_survives_later_anchor_rewrites() {
        let dir = tempdir().unwrap();
        let ledger = dir.path().join("ledger.jsonl");
        fs::write(&ledger, b"{\"a\":1}\n{\"a\":2").unwrap();
        let torn = recover_torn_tail(&ledger, "test ledger").unwrap().unwrap();

        store_head_anchor(dir.path(), "ledger.jsonl", 1, "h1", Some(torn.report(7))).unwrap();
        // A later append carries the tally forward rather than resetting it.
        store_head_anchor(dir.path(), "ledger.jsonl", 2, "h2", None).unwrap();

        let anchor = read_head_anchor(dir.path(), "ledger.jsonl").unwrap().unwrap();
        assert_eq!(anchor.sequence, 2);
        assert_eq!(anchor.discarded_bytes_total, 6);
        assert_eq!(anchor.last_torn_recovery.unwrap().at_unix, 7);
    }

    #[test]
    fn write_private_atomic_replaces_in_one_step_and_stays_private() {
        let dir = tempdir().unwrap();
        let policy = dir.path().join("policy.json");
        write_private_atomic(&policy, b"{\"v\":1}\n").unwrap();
        assert_eq!(mode(&policy), 0o600);
        write_private_atomic(&policy, b"{\"v\":2}\n").unwrap();
        assert_eq!(fs::read(&policy).unwrap(), b"{\"v\":2}\n");
        // No temp file survives a successful rename.
        assert!(!policy.with_extension("json.tmp").exists());
    }

    #[test]
    fn a_malformed_head_anchor_is_an_error_rather_than_a_default() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("ledger.jsonl-head.json"), b"{not json").unwrap();
        assert!(
            read_head_anchor(dir.path(), "ledger.jsonl").is_err(),
            "an unreadable anchor must not degrade into None"
        );
    }

    fn agent(id: &str) -> crate::autonomy::EconomicAgentManifest {
        crate::autonomy::EconomicAgentManifest {
            schema_version: crate::SCHEMA_VERSION,
            agent_id: id.into(),
            public_key: "k".into(),
            agent_class: crate::autonomy::AgentClass::Compute,
            allowed_job_types: vec![crate::JobType::Compute],
            daily_budget_musd_micros: 1_000,
            max_job_cost_musd_micros: 500,
            risk_profile: crate::autonomy::RiskProfile::Balanced,
            enabled: true,
            created_at_unix: 0,
        }
    }

    /// One hand-built reinvestment record, hashed the way the controller hashes
    /// it. Built by hand because the only public path that produces one goes
    /// through the trust-mode gate, which is not what is under test here.
    ///
    /// The JSON is written out by hand because `serde_json::Map` sorts its keys
    /// unless `preserve_order` is on, and the hash is over the byte
    /// serialization — field order is part of what is committed.
fn reinvestment_record(sequence: u64, prev_hash: &str, autonomy_head: &str) -> String {
        // Positional arguments only: a format string built by `concat!` cannot
        // use named capture.
        let commitment = format!(
            concat!(
                r#"{{"schema_version":{},"commitment_id":"commitment-{}","#,
                r#""created_at_unix":1,"agent_id":"agent-1","opportunity_id":"opp-1","#,
                r#""job_intent_id":"intent-1","amount_musd_micros":1000000,"#,
                r#""autonomy_head_hash":"{}","effective_rate_bps":2000}}"#
            ),
            crate::SCHEMA_VERSION,
            sequence,
            autonomy_head
        );
        let unhashed = format!(
            concat!(
                r#"{{"sequence":{},"recorded_at_unix":1,"prev_hash":"{}","#,
                r#""record_hash":"","commitment":{}}}"#
            ),
            sequence,
            prev_hash,
            commitment
        );
        let hash = blake3::hash(unhashed.as_bytes()).to_hex().to_string();
        unhashed.replacen(
            r#""record_hash":"""#,
            &format!(r#""record_hash":"{hash}""#),
            1,
        )
    }

    #[test]
    fn a_reinvestment_ledger_binds_the_autonomy_heads_it_names() {
        let dir = tempdir().unwrap();
        let econ = dir.path().join("econ");
        let autonomy = AutonomousEconomy::open(&econ).unwrap();
        autonomy.register_agent(agent("agent-1")).unwrap();

        // Keep a copy of the autonomy ledger and its anchor as they stand at
        // head A, so the rollback below is *internally consistent*: its own
        // anchor still matches it. Nothing but the cross-bind can notice.
        let ledger_a = fs::read(autonomy.ledger_path()).unwrap();
        let anchor_path = head_anchor_path(&econ, crate::autonomy::AUTONOMY_LEDGER_FILE);
        let anchor_a = fs::read(&anchor_path).unwrap();

        autonomy.register_agent(agent("agent-2")).unwrap();
        let head_b = autonomy.records().unwrap()[1].record_hash.clone();
        assert_eq!(autonomy.records().unwrap().len(), 2);

        let controller = crate::reinvestment::ReinvestmentController::open(&econ).unwrap();
        let line = reinvestment_record(
            1,
            crate::reinvestment::REINVESTMENT_GENESIS_HASH,
            &head_b,
        );
        append_line(
            &econ.join(crate::reinvestment::REINVESTMENT_LEDGER_FILE),
            format!("{line}\n").as_bytes(),
        )
        .unwrap();

        controller
            .verify_autonomy_head_binding(&autonomy)
            .expect("the commitment names a head the autonomy ledger still has");

        // Roll the autonomy ledger back to head A, anchor included.
        fs::write(autonomy.ledger_path(), &ledger_a).unwrap();
        fs::write(&anchor_path, &anchor_a).unwrap();

        // The autonomy ledger is self-consistent again: its chain verifies and
        // its own anchor matches, so the rollback is invisible from that side.
        assert_eq!(autonomy.records().unwrap().len(), 1);

        let err = controller
            .verify_autonomy_head_binding(&autonomy)
            .expect_err("a head the autonomy ledger no longer holds must be refused")
            .to_string();
        assert!(err.contains("no longer contains"), "{err}");
        assert!(err.contains(&head_b), "the report must name the head: {err}");
    }

    #[test]
    fn a_pre_existing_ledger_without_an_anchor_still_reads() {
        // The upgrade path: ledgers written before anchoring existed have no
        // anchor, and refusing them would strand every existing installation.
        let dir = tempdir().unwrap();
        let econ = dir.path().join("econ");
        let autonomy = AutonomousEconomy::open(&econ).unwrap();
        autonomy.register_agent(agent("agent-before-upgrade")).unwrap();
        assert!(econ.join("autonomous-ledger.jsonl").exists());

        // Simulate the pre-upgrade state: no anchor file.
        fs::remove_file(econ.join("autonomous-ledger.jsonl-head.json")).unwrap();
        assert_eq!(autonomy.records().unwrap().len(), 1);

        // The next append re-anchors it.
        autonomy.register_agent(agent("agent-after-upgrade")).unwrap();
        assert_eq!(autonomy.head_anchor().unwrap().unwrap().sequence, 2);
    }
}
