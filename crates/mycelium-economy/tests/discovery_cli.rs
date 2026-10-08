//! End-to-end checks on the P6 CLI surface: `discovery-run`,
//! `discovery-observe`, `discovery-status` and `discovery-validate-policy`.
//!
//! These drive the real binary, with a real MUPP state file on disk and a real
//! S1 perception report, because the properties under test are exactly the ones
//! an operator would meet at the command line:
//!
//! * a scan that measured a negative is `no_edge` with that measurement in the
//!   report — the evidence `s1_perception_adapter` computes and every other
//!   consumer discarded;
//! * a scan that completed, found nothing, and measured nothing is
//!   `invalid_evidence`, not `no_edge`;
//! * a scan that ran hot is `search_aborted_thermal`, not `no_edge`, and it
//!   contributes no coverage;
//! * a stale or blocked MUPP state stops the search entirely, and
//!   `discovery-run` takes the MUPP path as a **required positional argument** so
//!   that cannot be skipped by omission — the gap the audit found, where the
//!   existing thermal brake is opt-in;
//! * `no_edge` on arbitrage never yields "no external value exists": six of the
//!   seven classes have no adapter and the report says so;
//! * a caller-supplied `min_net_edge` of 0 is refused with a named reason;
//! * the degenerate case a caller can still reach — an operator opening
//!   `EconomicPolicy::min_net_edge_musd_micros` — is recorded with its surface.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
use mycelium_economy::discovery::SEARCH_MEMORY_FILE;

const BIN: &str = env!("CARGO_BIN_EXE_mycelium-economy");
const DEV_PROVIDER_ENV: &str = "MYCELIUM_DEV_BASE_PROVIDER";

/// Real wall-clock seconds, because the CLI reads MUPP with the real clock and
/// `MuppAdapterPolicy`'s default maximum age is 180 s. A fixture stamped with a
/// made-up constant would be stale before the test started.
fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs_f64()
}

/// A scratch home plus a MUPP state file and a scratch source directory.
struct Cli {
    /// Held so the scratch tree outlives the fixture. Never read: the temp dir's
    /// own `Drop` is the whole point.
    #[allow(dead_code)]
    dir: tempfile::TempDir,
    home: PathBuf,
    mupp: PathBuf,
    src: PathBuf,
}

impl Cli {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        fs::create_dir_all(&home).unwrap();
        let mupp = dir.path().join("mupp-state.json");
        let src = dir.path().join("src");
        fs::create_dir_all(&src).unwrap();
        let mut cli = Self { dir, home, mupp, src };
        cli.write_mupp(true, 12.0, "IDLE");
        cli
    }

    /// Writes a MUPP state stamped now. `allow` and `headroom` are what the
    /// machine would read; the search only happens when the state is fresh and
    /// the gate is open.
    fn write_mupp(&mut self, allow: bool, headroom: f64, phase: &str) {
        self.write_mupp_at(now(), allow, headroom, phase);
    }

    /// Writes a MUPP state with an explicit timestamp, so a test can make it
    /// stale (an old stamp) or implausibly new (a stamp ahead of the CLI's
    /// clock, which is what makes `read_mupp_gate` clamp the age to zero).
    fn write_mupp_at(&mut self, timestamp: f64, allow: bool, headroom: f64, phase: &str) {
        let state = serde_json::json!({
            "schema_version": 1,
            "timestamp_unix": timestamp,
            "mode": "MUPP_LOCAL_CONTROL",
            "regime": "ECO",
            "phase": phase,
            "T": 60.0 + headroom,
            "H": headroom,
            "RecoveryDebt": 0.0,
            "sensor_ok": true,
            "sensor_warmup_complete": true,
            "allow_execution": allow,
            "cpu_temp_c": 60.0,
            "gpu_temp_c": 50.0,
            "cpu_util_pct": 10.0,
            "gpu_util_pct": 0.0,
            "queue": 0
        });
        fs::write(&self.mupp, serde_json::to_vec(&state).unwrap()).unwrap();
    }

    /// A perception report shaped exactly as `import_perception_report` demands:
    /// `cycles_requested`/`cycles_completed`/`started_at`/`events`/`candidates`,
    /// non-Anvil, `broadcast: false`.
    fn write_perception(
        &self,
        name: &str,
        best_edge: Option<i64>,
        best_robust: Option<i64>,
        end_temp_c: f64,
    ) -> PathBuf {
        let path = self.src.join(name);
        let report = serde_json::json!({
            "mode": "PERCEPTION_SHADOW",
            "status": "COMPLETED",
            "cycles_requested": 2,
            "cycles_completed": 2,
            "started_at": now(),
            "chain_id": 8453,
            "measured": true,
            "broadcast": false,
            "profit_is_real": false,
            "anvil": false,
            "best_observed_token_edge_usdc_raw": best_edge,
            "best_observed_robust_net_usdc_raw": best_robust,
            "thermal_start_window": { "max": 55.0 },
            "end_temp_c": end_temp_c,
            // Two events: the aggregate is a maximum, so the worst event must not
            // be the one the report summarises. With no measurement at all the
            // scan also reports no events, which is the case P6 must refuse to
            // read as a negative edge.
            "events": match best_robust {
                None => serde_json::json!([]),
                Some(robust) => serde_json::json!([
                    { "near_edge_refinement": {
                        "best_refined_edge_usdc_raw": -90_000,
                        "best_refined_robust_net_usdc_raw": -9_000_000
                    } },
                    { "near_edge_refinement": {
                        "best_refined_edge_usdc_raw": best_edge.unwrap_or(-1),
                        "best_refined_robust_net_usdc_raw": robust
                    } }
                ]),
            },
            "candidates": []
        });
        fs::write(&path, serde_json::to_vec(&report).unwrap()).unwrap();
        path
    }

    fn run(&self, args: &[&str]) -> std::process::Output {
        Command::new(BIN)
            .arg("--home")
            .arg(&self.home)
            .args(args)
            .env_remove(DEV_PROVIDER_ENV)
            .output()
            .expect("run mycelium-economy")
    }

    fn ok(&self, args: &[&str]) -> serde_json::Value {
        let out = self.run(args);
        assert!(
            out.status.success(),
            "{args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).expect("valid json")
    }

    fn run_search(&self, source: &Path) -> serde_json::Value {
        self.ok(&[
            "discovery-run",
            &source.display().to_string(),
            "s1",
            "0.05",
            "120",
            &self.mupp.display().to_string(),
        ])
    }

    fn memory_path(&self) -> PathBuf {
        self.home.join(SEARCH_MEMORY_FILE)
    }
}

#[test]
fn a_measured_negative_scan_is_no_edge_and_keeps_its_measurement() {
    let cli = Cli::new();
    let source = cli.write_perception("negative.json", Some(-32_674), Some(-2_032_674), 58.0);
    let report = cli.run_search(&source);

    assert_eq!(report["observation_state_name"], "no_edge");
    assert_eq!(report["state_name"], "no_edge");
    assert_eq!(report["action_name"], "backoff_and_continue_search");
    assert_eq!(report["completed"], true);

    // The measurement that used to be printed and dropped is now the evidence for
    // the conclusion.
    let edge = &report["observation_state"]["detail"]["edge"];
    assert_eq!(edge["robust_net_micros"], -2_032_674);
    assert_eq!(edge["token_edge_micros"], -32_674);
    assert_eq!(edge["source_field"], "near_edge_refinement");

    // And it is a negative edge, not an absent one.
    let reason = report["reason"].as_str().unwrap();
    assert!(reason.contains("-2032674"), "{reason}");
    assert!(reason.contains("measured negative"), "{reason}");

    assert_eq!(report["promotion"], serde_json::Value::Null);
    assert!(cli.memory_path().exists(), "backoff survives the process");
}

#[test]
fn no_edge_on_one_class_never_claims_that_no_external_value_exists() {
    let cli = Cli::new();
    let source = cli.write_perception("negative.json", Some(-1), Some(-1), 58.0);
    let report = cli.run_search(&source);

    assert_eq!(report["state_name"], "no_edge");
    assert_eq!(report["concludes_no_external_value_exists"], false);

    // Six of the seven classes have no adapter and the report says which.
    let unsupported: Vec<&str> = report["class_coverage"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["support"] == "unsupported")
        .map(|r| r["class"].as_str().unwrap())
        .collect();
    assert_eq!(unsupported.len(), 6, "{unsupported:?}");
    assert_eq!(unsupported[0], "solver_reward");
    assert_eq!(unsupported[5], "network_fee");

    // `no_edge` on the one implemented class is reported as coverage on that
    // class only; the others stay at zero attempts.
    let implemented: Vec<&serde_json::Value> = report["class_coverage"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["support"] == "implemented")
        .collect();
    assert_eq!(implemented.len(), 1);
    assert_eq!(implemented[0]["class"], "arbitrage");
    for row in report["class_coverage"].as_array().unwrap() {
        if row["support"] == "unsupported" {
            assert_eq!(row["cycles_attempted"], 0);
            assert_eq!(row["candidates_found"], 0);
        }
    }
}

#[test]
fn a_completed_scan_with_no_candidate_and_no_measurement_is_invalid_evidence() {
    let cli = Cli::new();
    let source = cli.write_perception("unmeasured.json", None, None, 58.0);
    let report = cli.run_search(&source);

    // Not `no_edge`: the machine will not conclude "nothing there" from the
    // absence of a finding.
    assert_eq!(report["state_name"], "invalid_evidence");
    assert_ne!(report["state_name"], "no_edge");
    assert_eq!(report["action_name"], "fail_closed");
    assert_eq!(report["completed"], false);
    assert_eq!(report["state"]["detail"]["defect"]["defect"], "unmeasured");
}

#[test]
fn a_scan_that_ran_hot_is_a_thermal_stop_and_contributes_no_coverage() {
    let cli = Cli::new();
    // 93 C is the peak this hardware was actually observed to reach.
    let source = cli.write_perception("hot.json", Some(-1), Some(-1), 93.0);
    let report = cli.run_search(&source);

    assert_eq!(report["state_name"], "search_aborted_thermal");
    assert_ne!(report["state_name"], "no_edge");
    assert_eq!(report["action_name"], "enter_thermal_cooldown");
    assert_eq!(report["completed"], false);
    assert_eq!(report["state"]["detail"]["stop"]["stop"], "budget_temperature");
    assert_eq!(report["coverage"]["cycles_completed"], 0);
    assert_eq!(report["coverage"]["cycles_attempted"], 0);
    let reason = report["reason"].as_str().unwrap();
    assert!(reason.contains("NOT a negative edge"), "{reason}");
}

#[test]
fn a_blocked_or_stale_mupp_state_stops_the_search_before_anything_is_concluded() {
    let mut cli = Cli::new();
    let source = cli.write_perception("negative.json", Some(-1), Some(-1), 58.0);

    // MUPP hard-blocked at a perfectly ordinary temperature.
    cli.write_mupp(false, 12.0, "COLLAPSE");
    let blocked = cli.run_search(&source);
    assert_eq!(blocked["state_name"], "search_aborted_thermal");
    assert_eq!(blocked["denied"]["denied"], "thermal");
    assert_eq!(blocked["denied"]["detail"]["stop"]["stop"], "mupp_hard_blocked");
    assert_eq!(blocked["completed"], false);

    // A stale state. `read_mupp_gate` refuses it outright here, and P6 separates
    // "old" from "hot" rather than letting one number stand for both.
    cli.write_mupp_at(now() - 3_600.0, true, 12.0, "IDLE");
    let stale = cli.run_search(&source);
    assert_eq!(stale["state_name"], "search_aborted_thermal");
    assert_eq!(stale["denied"]["detail"]["stop"]["stop"], "stale_state");
    assert_eq!(stale["completed"], false);
}

#[test]
fn a_caller_clock_earlier_than_the_mupp_state_is_refused_by_name() {
    // The audit's finding: `read_mupp_gate` clamps a negative age to 0, so a
    // caller who picks an earlier clock reads a stale state as fresh. P6 refuses
    // the pair instead and says which of the two situations it was.
    let mut cli = Cli::new();
    let source = cli.write_perception("negative.json", Some(-1), Some(-1), 58.0);
    // The state claims to be from an hour in the future. `read_mupp_gate` clamps
    // the resulting negative age to 0 and reports the state as fresh; P6 refuses
    // the pair.
    cli.write_mupp_at(now() + 3_600.0, true, 12.0, "IDLE");
    let report = cli.run_search(&source);
    assert_eq!(report["state_name"], "search_aborted_thermal");
    assert_eq!(
        report["denied"]["detail"]["stop"]["stop"],
        "clock_went_backwards"
    );
}

#[test]
fn discovery_run_requires_a_mupp_state_path_positionally() {
    let cli = Cli::new();
    let source = cli.write_perception("negative.json", Some(-1), Some(-1), 58.0);
    let source_arg = source.display().to_string();
    let out = cli.run(&["discovery-run", &source_arg, "s1", "0.05", "120"]);
    assert!(!out.status.success(), "a search may not run without a MUPP state");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Usage"), "{stderr}");
}

#[test]
fn discovery_status_reports_the_health_vector_and_never_a_fused_score() {
    let cli = Cli::new();
    let fresh = cli.ok(&["discovery-status"]);
    assert_eq!(fresh["cycle"], 0);
    assert_eq!(fresh["health_verdict"]["verdict"], "insufficient");
    assert_eq!(fresh["health"]["diversity"]["distinct_routes"], 0);
    assert_eq!(fresh["adapters"]["arbitrage"], "s1_shadow_scan");
    assert_eq!(
        fresh["searchable_classes"],
        serde_json::json!(["arbitrage"]),
        "only the class with an adapter is searchable"
    );
    // The vector is reported as a vector.
    assert!(fresh["health"].get("fitness").is_none());
    assert!(fresh["health"].get("score").is_none());
    assert!(fresh["health"].get("total").is_none());

    let source = cli.write_perception("negative.json", Some(-1), Some(-1), 58.0);
    cli.run_search(&source);
    let after = cli.ok(&["discovery-status"]);
    assert_eq!(after["cycle"], 1);
    assert_eq!(after["state_name"], "no_edge");
    assert_eq!(after["cold"]["searched_classes"], 0);
    assert_eq!(after["cold"]["unsupported"].as_array().unwrap().len(), 6);
    let stderr_note = after["note"].as_str().unwrap();
    assert!(stderr_note.contains("no authority input reads it"), "{stderr_note}");
}

#[test]
fn discovery_validate_policy_refuses_a_degenerate_min_net_edge() {
    let cli = Cli::new();

    let ok = cli.ok(&["discovery-validate-policy", "0.01"]);
    assert_eq!(ok["valid"], true);
    assert_eq!(ok["min_net_edge_musd_micros"], 10_000);
    assert_eq!(ok["promotion_blocked_by_degenerate_threshold"], false);
    assert_eq!(ok["hard_thermal_ceiling_c"], 75.0);
    // The 93 C peak observed on this hardware is above the hard ceiling, so a
    // budget cannot be configured to authorise the run that produced it.
    assert!(ok["budget"]["max_observed_temperature_c"].as_f64().unwrap() < 93.0);

    let out = cli.run(&["discovery-validate-policy", "0"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("unrepresentable"), "{stderr}");
    assert!(stderr.contains("trivially pass"), "{stderr}");
}

#[test]
fn discovery_validate_policy_records_which_surface_a_threshold_came_from() {
    let cli = Cli::new();
    let out = cli.ok(&["discovery-validate-policy", "0.01"]);
    let records = out["thresholds"]["records"].as_array().unwrap();
    let names: Vec<&str> = records.iter().map(|r| r["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"min_net_edge_musd_micros"));
    assert!(names.contains(&"discovery::MinNetEdge::CRATE_DEFAULT_MICROS"));
    assert!(names.contains(&"discovery::HARD_THERMAL_CEILING_C"));
    for record in records {
        let source = record["source"]["source"].as_str().unwrap();
        assert!(
            source == "crate_default" || source == "caller_supplied",
            "{record}"
        );
        assert_eq!(record["degenerate"], false);
    }
    // The caller-supplied one names the surface it came from.
    let caller = records
        .iter()
        .find(|r| r["name"] == "min_net_edge_musd_micros")
        .unwrap();
    assert_eq!(
        caller["source"]["detail"]["surface"],
        "autonomy::EconomicPolicy"
    );
}

#[test]
fn discovery_observe_classifies_external_evidence_and_refuses_a_forged_observation() {
    let cli = Cli::new();
    let cycle = 1i64;
    let observation = serde_json::json!({
        "schema_version": 1,
        "class": "arbitrage",
        "adapter": "external_scanner",
        "cycle": cycle,
        "cycles_budgeted": 2,
        "cycles_completed": 2,
        "cells_scanned": 128,
        "aborted": false,
        "candidates": [],
        "best_observed_edge": {
            "token_edge_micros": -1_000,
            "robust_net_micros": -90_000,
            "source_field": "external_pool_scan"
        },
        "settlement": { "settlement": "not_applicable" },
        "valuation": { "valuation": "not_required" },
        "thermal": { "start_max_c": 40.0, "end_c": 41.0 },
        "spend": {
            "cycles": 2,
            "wall_ms": 100,
            "cpu_ms": 90,
            "energy_mj": 500,
            "rpc_calls": 12,
            "peak_temperature_c": 41.0
        },
        "resolution": null,
        "defect": null
    });
    let path = cli.src.join("observation.json");
    fs::write(&path, serde_json::to_vec(&observation).unwrap()).unwrap();

    // Evidence that disagrees with the permit it was issued for is refused at the
    // boundary rather than silently relabelled. Checked before the valid
    // observation, because a successful observation exhausts the class and the
    // next call would be denied a permit for an unrelated reason.
    let mut forged = observation.clone();
    forged["cycle"] = serde_json::json!(99);
    let forged_path = cli.src.join("forged.json");
    fs::write(&forged_path, serde_json::to_vec(&forged).unwrap()).unwrap();
    let out = cli.run(&[
        "discovery-observe",
        &forged_path.display().to_string(),
        &cli.mupp.display().to_string(),
    ]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("disagrees with the permit"), "{stderr}");

    let report = cli.ok(&[
        "discovery-observe",
        &path.display().to_string(),
        &cli.mupp.display().to_string(),
    ]);
    assert_eq!(report["observation_state_name"], "no_edge");
    // Cells were reported and processed, one cycle minimum met, so the class may
    // be declared exhausted.
    assert_eq!(report["state_name"], "class_exhausted");
    assert_eq!(report["action_name"], "rotate_class");
    assert_eq!(report["coverage"]["cells_scanned"], 128);
    assert_eq!(report["promotion"], serde_json::Value::Null);

    // Exhausted, and nothing else is searchable: the machine goes cold and says
    // which six classes have no adapter rather than calling the market empty.
    let cold = cli.ok(&["discovery-status"]);
    assert_eq!(cold["state_name"], "class_exhausted");
    assert_eq!(cold["cold"]["exhausted"], serde_json::json!(["arbitrage"]));
    assert_eq!(cold["cold"]["searched_classes"], 1);
    let denied = cli.run(&[
        "discovery-observe",
        &path.display().to_string(),
        &cli.mupp.display().to_string(),
    ]);
    assert!(denied.status.success());
    let denied = serde_json::from_slice::<serde_json::Value>(&denied.stdout).unwrap();
    assert_eq!(denied["state_name"], "cold_discovery");
    assert_eq!(denied["completed"], false);
}

#[test]
fn discovery_observe_cannot_promote_an_unimplemented_class() {
    // Six classes have no adapter in this crate. An external observation naming
    // one is still refused a permit for it, because support is decided by the
    // machine's own registry and not by the observation.
    let cli = Cli::new();
    let observation = serde_json::json!({
        "schema_version": 1,
        "class": "storage_reward",
        "adapter": "external_scanner",
        "cycle": 1,
        "cycles_budgeted": 2,
        "cycles_completed": 2,
        "cells_scanned": 128,
        "aborted": false,
        "candidates": [],
        "best_observed_edge": {
            "token_edge_micros": -1_000,
            "robust_net_micros": -90_000,
            "source_field": "external_pool_scan"
        },
        "settlement": { "settlement": "not_applicable" },
        "valuation": { "valuation": "not_required" },
        "thermal": { "start_max_c": 40.0, "end_c": 41.0 },
        "spend": {
            "cycles": 2,
            "wall_ms": 100,
            "cpu_ms": 90,
            "energy_mj": 500,
            "rpc_calls": 12,
            "peak_temperature_c": 41.0
        },
        "resolution": null,
        "defect": null
    });
    let path = cli.src.join("storage.json");
    fs::write(&path, serde_json::to_vec(&observation).unwrap()).unwrap();

    // The permit is always for arbitrage, the one class with an adapter, so the
    // class mismatch is caught before anything is classified.
    let out = cli.run(&[
        "discovery-observe",
        &path.display().to_string(),
        &cli.mupp.display().to_string(),
    ]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("disagrees with the permit"), "{stderr}");
    assert!(stderr.contains("storage_reward"), "{stderr}");
}

#[test]
fn existing_commands_still_work_alongside_the_discovery_surface() {
    // Nothing here changed a gate, so the pre-existing commands keep working
    // unchanged.
    let cli = Cli::new();
    let autonomy = cli.ok(&["autonomy-status"]);
    assert_eq!(autonomy["trust_mode"], "unverified");
    assert_eq!(autonomy["opportunities"], 0);
    assert_eq!(autonomy["job_intents"], 0);
    let audit = cli.ok(&["autonomy-audit"]);
    assert_eq!(audit["valid"], true);
    let reinvest = cli.ok(&["reinvestment-status"]);
    assert_eq!(reinvest["ledger_valid"], true);
    assert_eq!(reinvest["committed_total_musd"], 0.0);
    let terr = cli.ok(&["terr-status"]);
    assert_eq!(terr["ledger_valid"], true);
    let dashboard = cli.ok(&["economy-dashboard"]);
    assert_eq!(dashboard["invariants"]["terr_can_authorize_capital"], false);
    assert_eq!(
        dashboard["invariants"]["stored_proof_verified_is_authority"],
        false
    );
    let mupp = cli.ok(&["mupp-gate", &cli.mupp.display().to_string()]);
    assert_eq!(mupp["fresh"], true);
    assert_eq!(mupp["allow_execution"], true);
}