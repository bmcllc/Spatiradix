//! End-to-end durability checks against the CLI.
//!
//! These run the real binary so that two properties can be asserted that a
//! library-level test cannot reach:
//!
//! * the world-writable-directory correction is actually **reported** — the
//!   warning goes to the process's stderr, which only a subprocess can capture
//!   (`std` offers no in-process stdout/stderr capture);
//! * the append lock holds across **processes**, not just threads. Two CLI
//!   invocations racing on the same home is the exact shape of the duplicate
//!   `sequence` the lock exists to prevent.
//!
//! In-process and library-level behaviour is covered by the `durability` unit
//! tests inside the crate.

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Output},
};
use tempfile::tempdir;

const BIN: &str = env!("CARGO_BIN_EXE_mycelium-economy");

fn run(home: &Path, args: &[&str]) -> Output {
    Command::new(BIN)
        .arg("--home")
        .arg(home)
        .args(args)
        .env_remove("MYCELIUM_DEV_BASE_PROVIDER")
        .output()
        .expect("run mycelium-economy")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
}

/// Byte offsets of every complete-line terminator.
fn newline_offsets(bytes: &[u8]) -> Vec<usize> {
    bytes
        .iter()
        .enumerate()
        .filter(|(_, b)| **b == b'\n')
        .map(|(i, _)| i)
        .collect()
}

fn job(id: &str) -> [&str; 7] {
    [
        "job-create",
        "compute",
        "requester-1",
        "input-hash-1",
        "1.0",
        "false",
        id,
    ]
}

fn manifest(id: &str, path: &Path) -> String {
    let manifest = serde_json::json!({
        "schema_version": 1,
        "agent_id": id,
        "public_key": format!("{id}-key"),
        "agent_class": "compute",
        "allowed_job_types": ["compute"],
        "daily_budget_musd_micros": 1_000_000,
        "max_job_cost_musd_micros": 500_000,
        "risk_profile": "balanced",
        "enabled": true,
        "created_at_unix": 0,
    });
    fs::write(path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    path.display().to_string()
}

#[test]
fn ledgers_and_the_economy_root_are_created_private() {
    let home = tempdir().unwrap();
    let econ = home.path().join("econ");
    // A root that does not exist yet, under the default umask.
    assert!(!econ.exists());

    let out = run(&econ, &job("job-1"));
    assert!(out.status.success(), "{}", stderr(&out));

    assert_eq!(
        mode(&econ),
        0o700,
        "economy root must be owner-only, was {:04o}",
        mode(&econ)
    );
    let ledger = econ.join("revenue-ledger.jsonl");
    assert_eq!(
        mode(&ledger),
        0o600,
        "ledger must be owner-read/write only, was {:04o}",
        mode(&ledger)
    );
    // The head anchor is a ledger of the head; same rules.
    assert_eq!(
        mode(&econ.join("revenue-ledger.jsonl-head.json")),
        0o600,
        "head anchor must be 0600"
    );
    // So is the policy file, which carries the payout address.
    let init = run(
        &econ,
        &["payment-policy-init", "0x1234567890abcdef1234567890abcdef12345678", "2"],
    );
    assert!(init.status.success(), "{}", stderr(&init));
    assert_eq!(mode(&econ.join("payment-policy.json")), 0o600);
    // And the lock directory, which holds a bound socket.
    assert_eq!(mode(&econ.join(".locks")), 0o700);
}

#[test]
fn pre_existing_world_writable_directory_is_corrected_and_reported() {
    let home = tempdir().unwrap();
    let econ = home.path().join("econ");
    fs::create_dir_all(&econ).unwrap();
    // The state an installation created before hardening existed has.
    fs::set_permissions(&econ, fs::Permissions::from_mode(0o777)).unwrap();
    assert_eq!(mode(&econ), 0o777, "sanity: world-writable before the run");

    let out = run(&econ, &job("job-1"));
    assert!(out.status.success(), "{}", stderr(&out));

    assert_eq!(
        mode(&econ),
        0o700,
        "a wrong mode must be corrected, not merely reported"
    );
    let err = stderr(&out);
    assert!(
        err.contains("WARN") && err.contains("0777") && err.contains("0700"),
        "the correction must be reported, naming both modes: {err}"
    );
    assert!(
        err.contains("finding"),
        "the report must state that the wrong mode is itself a finding: {err}"
    );
}

#[test]
fn pre_existing_world_readable_ledger_is_corrected_on_the_next_append() {
    let home = tempdir().unwrap();
    let econ = home.path().join("econ");
    assert!(run(&econ, &job("job-1")).status.success());

    let ledger = econ.join("revenue-ledger.jsonl");
    fs::set_permissions(&ledger, fs::Permissions::from_mode(0o644)).unwrap();

    let out = run(&econ, &job("job-2"));
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(mode(&ledger), 0o600);
    assert!(
        stderr(&out).contains("0644") && stderr(&out).contains("0600"),
        "the file-mode correction must be reported: {}",
        stderr(&out)
    );
}

#[test]
fn concurrent_cli_appends_produce_one_valid_chain_without_duplicate_sequence() {
    // The regression for the missing lock: before it, every process read the
    // same tail and derived the same `sequence`, so the chain either broke or
    // carried duplicates that were only ever *detected*, never prevented.
    const PROCESSES: usize = 12;

    let home = tempdir().unwrap();
    let econ = home.path().join("econ");

    let handles: Vec<_> = (0..PROCESSES)
        .map(|i| {
            let econ = econ.clone();
            std::thread::spawn(move || {
                let id = format!("job-{i}");
                let out = run(&econ, &job(&id));
                assert!(
                    out.status.success(),
                    "append {id} failed: {}",
                    stderr(&out)
                );
            })
        })
        .collect();
    for handle in handles {
        handle.join().expect("append thread");
    }

    let audit = run(&econ, &["audit-ledger"]);
    assert!(audit.status.success(), "{}", stderr(&audit));
    let v: serde_json::Value = serde_json::from_slice(&audit.stdout).unwrap();
    assert_eq!(
        v["records"], PROCESSES as u64,
        "every append must land exactly once: {v}"
    );

    // `records()` already enforces contiguous, strictly increasing sequences and
    // a matching hash chain; a duplicate would have failed the read above. This
    // is the belt-and-braces check that the raw lines agree.
    let raw = fs::read_to_string(econ.join("revenue-ledger.jsonl")).unwrap();
    let mut sequences: Vec<u64> = Vec::new();
    for line in raw.lines().filter(|l| !l.trim().is_empty()) {
        let record: serde_json::Value = serde_json::from_str(line).unwrap();
        sequences.push(record["sequence"].as_u64().unwrap());
    }
    sequences.sort_unstable();
    sequences.dedup();
    assert_eq!(sequences.len(), PROCESSES, "duplicate sequence in {sequences:?}");
    assert_eq!(*sequences.first().unwrap(), 1);
    assert_eq!(*sequences.last().unwrap(), PROCESSES as u64);
}

#[test]
fn truncated_tail_is_detected_through_the_separate_head_anchor() {
    let home = tempdir().unwrap();
    let econ = home.path().join("econ");
    for i in 0..5 {
        assert!(
            run(&econ, &job(&format!("job-{i}"))).status.success(),
            "append {i} failed"
        );
    }

    // The prefix of a truncated ledger is a perfectly valid shorter chain: the
    // hash chain, the contiguous sequence and the record hashes all still check
    // out. The separate anchor is the only thing that can see it.
    let ledger = econ.join("revenue-ledger.jsonl");
    let full = fs::read(&ledger).unwrap();
    let keep = newline_offsets(&full)
        .get(2)
        .copied()
        .expect("at least three complete records");
    let file = fs::OpenOptions::new().write(true).open(&ledger).unwrap();
    file.set_len((keep + 1) as u64).unwrap();
    file.sync_all().unwrap();
    drop(file);

    // The truncated prefix still parses as its own valid chain — that is what
    // makes this attack invisible without the separate anchor.
    let prefix: Vec<&[u8]> = full[..=keep].split(|b| *b == b'\n').collect();
    assert_eq!(prefix.len(), 4, "three complete records plus a trailing empty");

    let audit = run(&econ, &["audit-ledger"]);
    assert!(
        !audit.status.success(),
        "a truncated ledger must not audit clean: {}",
        String::from_utf8_lossy(&audit.stdout)
    );
    let err = stderr(&audit);
    assert!(
        err.contains("truncated") || err.contains("rolled back"),
        "the failure must name truncation: {err}"
    );
    assert!(
        err.contains("2 record(s) are missing"),
        "the failure must quantify the loss: {err}"
    );

    // Reads fail closed too, not just the audit command.
    assert!(!run(&econ, &["revenue"]).status.success());

    // The anchor is what detected it, and it is a separate file the truncation
    // did not touch.
    let anchor: serde_json::Value =
        serde_json::from_slice(&fs::read(econ.join("revenue-ledger.jsonl-head.json")).unwrap())
            .unwrap();
    assert_eq!(anchor["sequence"], 5);
}

#[test]
fn a_ledger_swapped_for_an_older_copy_is_detected() {
    let home = tempdir().unwrap();
    let econ = home.path().join("econ");
    for i in 0..4 {
        assert!(run(&econ, &job(&format!("job-{i}"))).status.success());
    }
    let ledger = econ.join("revenue-ledger.jsonl");
    let full = fs::read(&ledger).unwrap();
    let first = newline_offsets(&full).get(1).copied().unwrap() + 1;
    // An attacker keeps a copy of the first two records and restores it later.
    fs::write(&ledger, &full[..first]).unwrap();

    let audit = run(&econ, &["audit-ledger"]);
    assert!(!audit.status.success(), "an older copy must not audit clean");
    assert!(
        stderr(&audit).contains("rolled back"),
        "{}",
        stderr(&audit)
    );
}

#[test]
fn torn_final_line_is_recovered_and_the_discard_is_reported() {
    let home = tempdir().unwrap();
    let econ = home.path().join("econ");
    for i in 0..3 {
        assert!(run(&econ, &job(&format!("job-{i}"))).status.success());
    }
    let ledger = econ.join("revenue-ledger.jsonl");

    // Exactly what a crash between the record bytes and the newline leaves: a
    // valid prefix and a fragment that is not a record.
    let fragment = br#"{"sequence":4,"recorded_at_unix":1,"prev_hash":"#;
    let mut file = fs::OpenOptions::new().append(true).open(&ledger).unwrap();
    {
        use std::io::Write as _;
        file.write_all(fragment).unwrap();
    }
    file.sync_all().unwrap();
    drop(file);

    // A plain read self-heals rather than stranding the ledger forever, and it
    // says so out loud.
    let audit = run(&econ, &["audit-ledger"]);
    assert!(audit.status.success(), "{}", stderr(&audit));
    let err = stderr(&audit);
    assert!(err.contains("torn final record"), "{err}");
    assert!(err.contains("DISCARDED"), "the discard must be loud: {err}");
    assert!(
        err.contains(&ledger.display().to_string()),
        "the report must name the file: {err}"
    );

    let raw = fs::read_to_string(&ledger).unwrap();
    assert!(
        raw.ends_with('\n') && raw.lines().count() == 3,
        "exactly the three complete records must survive"
    );

    // And the amount discarded stays observable, not just in the log.
    let anchor: serde_json::Value =
        serde_json::from_slice(&fs::read(econ.join("revenue-ledger.jsonl-head.json")).unwrap())
            .unwrap();
    assert_eq!(
        anchor["discarded_bytes_total"],
        fragment.len() as u64,
        "the discarded byte count must be observable, not only logged"
    );
    assert_eq!(anchor["last_torn_recovery"]["discarded_bytes"], fragment.len());
    assert!(anchor["last_torn_recovery"].is_object());

    // The ledger is still writable: recovery leaves a valid chain behind.
    assert!(run(&econ, &job("job-4")).status.success());
    let v: serde_json::Value =
        serde_json::from_slice(&run(&econ, &["audit-ledger"]).stdout).unwrap();
    assert_eq!(v["records"], 4);
}

#[test]
fn autonomy_ledger_gets_the_same_treatment() {
    let home = tempdir().unwrap();
    let econ = home.path().join("econ");
    let manifest_path = home.path().join("manifest.json");

    let a = manifest("agent-a", &manifest_path);
    let first = run(&econ, &["agent-register-json", &a]);
    assert!(first.status.success(), "{}", stderr(&first));
    let b = manifest("agent-b", &manifest_path);
    let second = run(&econ, &["agent-register-json", &b]);
    assert!(second.status.success(), "{}", stderr(&second));

    let ledger = econ.join("autonomous-ledger.jsonl");
    assert_eq!(mode(&ledger), 0o600);
    assert_eq!(
        mode(&econ.join("autonomous-ledger.jsonl-head.json")),
        0o600
    );

    // Truncating the autonomy tail is caught the same way.
    let full = fs::read(&ledger).unwrap();
    assert!(newline_offsets(&full).len() >= 2);
    let file = fs::OpenOptions::new().write(true).open(&ledger).unwrap();
    file.set_len(0).unwrap();
    file.sync_all().unwrap();
    drop(file);

    let audit = run(&econ, &["autonomy-audit"]);
    assert!(!audit.status.success());
    assert!(
        stderr(&audit).contains("truncated"),
        "{}",
        stderr(&audit)
    );
}

#[test]
fn a_live_lock_holder_makes_an_append_refuse_rather_than_race() {
    let home = tempdir().unwrap();
    let econ = home.path().join("econ");
    assert!(run(&econ, &job("job-1")).status.success());

    let ledger = "revenue-ledger.jsonl";
    let held = mycelium_economy::durability::LedgerLock::acquire_timeout(
        &econ,
        ledger,
        std::time::Duration::from_millis(200),
    )
    .expect("acquire the lock");

    // A second holder is refused, and the refusal says what was given up.
    let refused = mycelium_economy::durability::LedgerLock::acquire_timeout(
        &econ,
        ledger,
        std::time::Duration::from_millis(200),
    );
    let text = match refused {
        Err(e) => e.to_string(),
        Ok(_) => panic!("a held lock must not be handed out twice"),
    };
    assert!(text.contains("ledger lock"), "{text}");
    assert!(text.contains("refusing to append"), "{text}");

    // Once released the lock is free again and leaves no residue.
    drop(held);
    mycelium_economy::durability::LedgerLock::acquire(&econ, ledger)
        .expect("the lock must be free after release");
    assert!(run(&econ, &job("job-2")).status.success());
    let v: serde_json::Value =
        serde_json::from_slice(&run(&econ, &["audit-ledger"]).stdout).unwrap();
    assert_eq!(v["records"], 2, "both records survive, in order");
}

#[test]
fn a_crashed_holders_lock_is_not_a_deadlock() {
    // A lock file left by a process that died is not a held lock: liveness is
    // read from /proc, so the lock is reclaimed the moment its holder is gone
    // rather than after a stale-lock timeout. A timer could not tell the
    // difference between dead and slow, and would either hang the daemon or
    // steal from a slow writer.
    let home = tempdir().unwrap();
    let econ = home.path().join("econ");
    let locks = econ.join(".locks");
    fs::create_dir_all(&locks).unwrap();
    fs::set_permissions(&locks, fs::Permissions::from_mode(0o700)).unwrap();
    // A pid no kernel hands out: /proc has no entry, so it is provably dead.
    let orphan = locks.join("revenue-ledger.jsonl.lock");
    // Written "just now" on purpose: only liveness, not age, can reclaim it.
    let now = std::time::UNIX_EPOCH.elapsed().map(|d| d.as_secs()).unwrap_or(0);
    fs::write(&orphan, format!("{}:1:{now}\n", 0x7FFF_FFFF)).unwrap();
    fs::set_permissions(&orphan, fs::Permissions::from_mode(0o600)).unwrap();

    let out = run(&econ, &job("job-1"));
    assert!(
        out.status.success(),
        "an abandoned lock must be reclaimable, not fatal: {}",
        stderr(&out)
    );
    assert!(
        stderr(&out).contains("reclaiming stale ledger lock"),
        "the reclaim must be reported: {}",
        stderr(&out)
    );
    assert!(
        stderr(&out).contains("its holder is gone"),
        "the reason must be that the holder is gone, not a timeout: {}",
        stderr(&out)
    );
    assert!(!orphan.exists(), "release must clear the lock file");

    let v: serde_json::Value =
        serde_json::from_slice(&run(&econ, &["audit-ledger"]).stdout).unwrap();
    assert_eq!(v["records"], 1);
}

// A live holder is never declared dead, however old its lock is, and a held
// lock is refused rather than raced. Both are covered where they can be
// asserted without waiting out `LEDGER_LOCK_WAIT`:
//   durability::tests::a_live_holders_lock_is_never_reclaimed
//   durability::tests::a_recycled_pid_is_not_mistaken_for_its_predecessor
//   durability::tests::an_unreadable_lock_is_never_broken_on_a_guess
//   durability::tests::the_lock_admits_exactly_one_holder_under_contention
