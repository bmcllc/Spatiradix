#!/usr/bin/env bash
# scripts/ci-test-gate.sh — CI test gate that cannot pass by running nothing.
#
# WHY THIS EXISTS. Exit status 0 is not, by itself, evidence that anything ran.
# Three verified methodology failures in this repo each produced, or nearly
# produced, a WRONG PASS, and all three are the same class of bug — the command
# succeeded while the thing we meant to check did not happen:
#
#   1. `cargo test` WITHOUT `--no-fail-fast` stops at the first failing test
#      binary. A green run was concealing real failures: 23 of 40 binaries had
#      never been reached. Cargo exits 0 for the binaries that passed and the
#      run simply stops; you cannot tell "all green" from "stopped early".
#   2. Piping cargo into `tee` reports TEE'S exit status, not cargo's. That
#      produced one genuine false pass across 8 feature checks. `tee` succeeds
#      as long as the pipe does not break. `${PIPESTATUS[0]}` is mandatory.
#   3. A WRONG TEST FILTER is the same bug wearing a different hat.
#      `cargo test -p mycelium-economy --locked concurrent_appends` exits 0
#      having run ZERO tests, because the real test is
#      `concurrent_cli_appends_produce_one_valid_chain_without_duplicate_sequence`
#      (crates/mycelium-economy/tests/ledger_durability.rs:171). A CI job keyed
#      on a filter that matches nothing is a silent no-op that reports SUCCESS.
#
# THE RULE ADOPTED: in this repo, exit 0 alone is no longer sufficient evidence.
# This script therefore does not just forward cargo's status — it counts what
# ran, prints it, and refuses to pass when the count says the gate did nothing.
#
# Legitimate zero-test components DO exist (e.g. `Running unittests
# src/bin/mycelium-economy.rs` legitimately reports `running 0 tests`), so the
# check is on the TOTAL across all binaries, never per binary. A single binary
# running zero next to binaries that ran tests is not a failure; EVERY binary
# running zero is.
#
# EXIT CODES
#   0  cargo passed AND the test-count checks passed.
#   1  cargo itself failed (build error or failing test). Real failure.
#   2  VACUOUS PASS — zero tests ran overall, or the total is below
#      --min-tests. The gate did not test anything it claimed to.
#   3  usage error (bad flag, missing label, cargo not on PATH).
#   4  a --expect-test target is absent from the run.
#
# USAGE
#   scripts/ci-test-gate.sh [OPTIONS] LABEL [CARGO ARGS...]
#
#   LABEL        human label used in the banner and the default log filename.
#   CARGO ARGS   forwarded verbatim to `cargo test`. `--no-fail-fast` is
#                added automatically when absent (never duplicated).
#
#   OPTIONS may appear before or after LABEL; only a bare `--` stops them from
#   being recognised, so an option after `--` is passed through to libtest.
#
# OPTIONS
#   --min-tests N     fail if the total number of tests run is below N.
#                     Default 1, which is exactly the zero-test detector.
#   --expect-test S   fail unless some test binary OR some executed test name
#                     contains the substring S. Repeatable. Used to assert that
#                     a specific suite really executed, e.g. a gate whose whole
#                     point is one named test.
#   --log PATH        where to write the full log. Default
#                     /tmp/ci-test-gate/<slug-of-label>.log.
#   -h, --help        this text.
#   --                end of options; everything after is the label + cargo args.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

usage() { sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed -e 's/^# \{0,1\}//' -e '$d'; }

die_usage() { printf 'ci-test-gate: %s\n\n' "$1" >&2; usage >&2; exit 3; }

MIN_TESTS=1
LOG_FILE=""
LABEL=""
declare -a EXPECT_TESTS=()
declare -a REST=()

# Options are recognised ANYWHERE before a `--` terminator, not only before the
# label. `--min-tests` / `--expect-test` / `--log` are not cargo flags, so
# consuming them out of position cannot swallow a real argument — and a gate that
# silently forwards its own `--min-tests` to cargo is precisely the kind of
# mis-wired check this script exists to prevent. Everything after the first
# non-option token is the LABEL plus the cargo arguments, in order.
SEEN_TERMINATOR=0
while [[ $# -gt 0 ]]; do
  if [[ "$SEEN_TERMINATOR" -eq 1 ]]; then
    REST+=("$1"); shift; continue
  fi
  case "$1" in
    --)
      # A `--` seen BEFORE the label is this script's option terminator and is
      # dropped. A `--` seen AFTER the label is cargo's own separator between its
      # flags and the libtest arguments, so it must survive into the cargo args --
      # eating it turns `-- --nocapture` into an unknown cargo flag.
      SEEN_TERMINATOR=1
      [[ ${#REST[@]} -eq 0 ]] || REST+=("--")
      shift ;;
    --min-tests)
      [[ $# -ge 2 ]] || die_usage "--min-tests requires a value"
      MIN_TESTS="$2"; shift 2 ;;
    --min-tests=*)
      MIN_TESTS="${1#*=}"; shift ;;
    --expect-test)
      [[ $# -ge 2 ]] || die_usage "--expect-test requires a value"
      EXPECT_TESTS+=("$2"); shift 2 ;;
    --expect-test=*)
      EXPECT_TESTS+=("${1#*=}"); shift ;;
    --log)
      [[ $# -ge 2 ]] || die_usage "--log requires a value"
      LOG_FILE="$2"; shift 2 ;;
    --log=*)
      LOG_FILE="${1#*=}"; shift ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      REST+=("$1"); shift ;;
  esac
done

[[ ${#REST[@]} -ge 1 ]] || die_usage "missing LABEL"
LABEL="${REST[0]}"
declare -a CARGO_ARGS=()
if [[ ${#REST[@]} -gt 1 ]]; then
  CARGO_ARGS=("${REST[@]:1}")
fi

[[ "$MIN_TESTS" =~ ^[0-9]+$ ]] || die_usage "--min-tests must be a non-negative integer, got: $MIN_TESTS"

command -v cargo >/dev/null 2>&1 || die_usage "cargo not found on PATH"

# ---- --no-fail-fast, always -------------------------------------------------
# Reason 1 above: without it cargo abandons the run at the first failing binary.
# Duplicate flags are harmless to cargo but make the log line confusing, so only
# add it when the caller did not already pass it.
declare -a CARGO_FINAL=()
HAVE_NO_FAIL_FAST=0
for a in ${CARGO_ARGS[@]+"${CARGO_ARGS[@]}"}; do
  CARGO_FINAL+=("$a")
  [[ "$a" == "--no-fail-fast" ]] && HAVE_NO_FAIL_FAST=1
done
if [[ "$HAVE_NO_FAIL_FAST" -eq 0 ]]; then
  CARGO_FINAL=(--no-fail-fast "${CARGO_FINAL[@]+"${CARGO_FINAL[@]}"}")
fi

if [[ -z "$LOG_FILE" ]]; then
  SLUG="$(printf '%s' "$LABEL" | tr -c '[:alnum:]._-' '-' | tr '[:upper:]' '[:lower:]')"
  [[ -n "$SLUG" ]] || SLUG="gate"
  LOG_FILE="/tmp/ci-test-gate/${SLUG}.log"
fi
mkdir -p "$(dirname "$LOG_FILE")"

printf '\n'
printf '=%.0s' {1..78}; printf '\n'
printf ' ci-test-gate: %s\n' "$LABEL"
printf '=%.0s' {1..78}; printf '\n'
printf ' command : cargo test %s\n' "${CARGO_FINAL[*]}"
printf ' log     : %s\n' "$LOG_FILE"
printf ' floor   : --min-tests %s\n' "$MIN_TESTS"
if [[ ${#EXPECT_TESTS[@]} -gt 0 ]]; then
  printf ' expect  : %s\n' "${EXPECT_TESTS[*]}"
fi
printf -- '-%.0s' {1..78}; printf '\n'

# ---- run cargo, tee the log, keep CARGO's status ----------------------------
# Reason 2 above. PIPESTATUS must be read in a SINGLE statement immediately after
# the pipeline: any intervening command — including a bare `x=${PIPESTATUS[0]}` —
# resets the array to that command's own status. tee is reported for diagnostics
# only and is NEVER used as the gate verdict.
set +e
cargo test "${CARGO_FINAL[@]}" 2>&1 | tee "$LOG_FILE"
PIPE_STATUS=("${PIPESTATUS[@]}")
set -e
CARGO_STATUS=${PIPE_STATUS[0]}
TEE_STATUS=${PIPE_STATUS[1]:-0}

# ---- parse what actually ran -----------------------------------------------
TSV="$(mktemp /tmp/ci-test-gate.XXXXXX.tsv)"
NAMES="$(mktemp /tmp/ci-test-gate.XXXXXX.names)"
TOTALS="$(mktemp /tmp/ci-test-gate.XXXXXX.tot)"
trap 'rm -f "$TSV" "$NAMES" "$TOTALS"' EXIT

# Columns: full_label <TAB> short_label <TAB> run <TAB> passed <TAB> failed
awk -v tsv="$TSV" -v names="$NAMES" -v totals="$TOTALS" '
function strip(s) { gsub(/\033\[[0-9;]*[A-Za-z]/, "", s); return s }
function flush() {
  if (label == "") return
  if (run < 0) run = 0
  printf "%s\t%s\t%d\t%d\t%d\n", label, short, run, passed, failed >> tsv
  nbin++
  total += run
  tpassed += passed
  tfailed += failed
  label = ""; short = ""; run = -1; passed = 0; failed = 0
}
{
  line = strip($0)
  # New test binary / doc-test section header.
  if (line ~ /^[ \t]+(Running|Doc-tests) /) {
    flush()
    sub(/^[ \t]+/, "", line)
    label = line
    short = line
    sub(/ \(target\/.*\)$/, "", short)
    if (short == "") short = label
    next
  }
  # Per-binary counters. Must precede the `test <name> ...` branch because
  # `test result: ...` also starts with "test ".
  if (line ~ /^[ \t]*running [0-9]+ tests?$/) {
    n = line; sub(/^.*running /, "", n); sub(/ tests?$/, "", n)
    run = n + 0
    next
  }
  if (line ~ /^[ \t]*test result:/) {
    if (match(line, /[0-9]+ passed/)) { p = substr(line, RSTART, RLENGTH); sub(/ passed$/, "", p); passed = p + 0 }
    if (match(line, /[0-9]+ failed/)) { f = substr(line, RSTART, RLENGTH); sub(/ failed$/, "", f); failed = f + 0 }
    flush()
    next
  }
  # Executed test names, for --expect-test. libtest names cannot contain spaces,
  # so requiring a space-free name keeps arbitrary --nocapture output from
  # forging an expectation match.
  if (line ~ /^[ \t]*test [^ \t]+ \.\.\. (ok|FAILED|ignored)/) {
    n = line; sub(/^[ \t]*test /, "", n); sub(/ \.\.\..*$/, "", n)
    print n >> names
    next
  }
}
END { flush(); printf "%d\t%d\t%d\t%d\n", nbin, total, tpassed, tfailed > totals }
' "$LOG_FILE"
read -r N_BIN TOTAL_TESTS TOTAL_PASSED TOTAL_FAILED < "$TOTALS" || true
N_BIN=${N_BIN:-0}; TOTAL_TESTS=${TOTAL_TESTS:-0}
TOTAL_PASSED=${TOTAL_PASSED:-0}; TOTAL_FAILED=${TOTAL_FAILED:-0}

# ---- per-binary summary: is the suite we expect actually visible? ----------
printf -- '-%.0s' {1..78}; printf '\n'
printf ' %-52s %7s %8s %7s\n' "TEST BINARY" "RUN" "PASSED" "FAILED"
printf -- '-%.0s' {1..78}; printf '\n'
if [[ -s "$TSV" ]]; then
  while IFS=$'\t' read -r full short run passed failed; do
    printf ' %-52.52s %7s %8s %7s\n' "$short" "$run" "$passed" "$failed"
  done < "$TSV"
else
  printf ' %-52s %7s %8s %7s\n' "(no test binary reported any counter)" 0 0 0
fi
printf -- '-%.0s' {1..78}; printf '\n'
printf ' binaries=%s  tests-run=%s  passed=%s  failed=%s  cargo-exit=%s (tee-exit=%s, ignored)\n' \
  "$N_BIN" "$TOTAL_TESTS" "$TOTAL_PASSED" "$TOTAL_FAILED" "$CARGO_STATUS" "$TEE_STATUS"
printf -- '-%.0s' {1..78}; printf '\n'

FAILURES=0

# ---- check 1: cargo's own verdict -------------------------------------------
if [[ "$CARGO_STATUS" -ne 0 ]]; then
  printf ' RESULT: FAIL — cargo exited %s (build error or failing test).\n' "$CARGO_STATUS"
  printf '        Full log: %s\n' "$LOG_FILE"
  FAILURES=1
fi

# ---- check 2: the total is not zero ----------------------------------------
# Reason 3 above. A filter that matches nothing, or a feature set that gates the
# whole suite off, both land here: cargo prints `running 0 tests` everywhere,
# every binary exits 0, and the job looks green.
if [[ "$TOTAL_TESTS" -eq 0 ]]; then
  printf '\n'
  printf '############################################################\n'
  printf '# VACUOUS PASS — ZERO TESTS RAN. THIS IS NOT A GREEN BUILD.  #\n'
  printf '############################################################\n'
  printf '# Label : %s\n' "$LABEL"
  printf '# cargo exited 0, but not one test binary reported a single\n'
  printf '# executed test. Almost always one of:\n'
  printf '#   * the test FILTER matches nothing (typo, or a test that was\n'
  printf '#     renamed/moved) — e.g. `concurrent_appends` vs the real\n'
  printf '#     concurrent_cli_appends_produce_one_valid_chain_without_duplicate_sequence\n'
  printf '#   * a #[cfg(feature = "...")] gate removed the whole suite\n'
  printf '#     (this workspace defaults to default = [], so `--features veil`\n'
  printf '#     is what actually runs the veil suites)\n'
  printf '#   * the -p / --test target selected does not exist\n'
  printf '# log: %s\n' "$LOG_FILE"
  printf '############################################################\n'
  if [[ "$FAILURES" -eq 0 ]]; then
    exit 2
  fi
  exit "$FAILURES"
fi

# ---- check 3: the total is at or above the floor ----------------------------
if [[ "$TOTAL_TESTS" -lt "$MIN_TESTS" ]]; then
  printf '\n'
  printf ' RESULT: FAIL — only %s test(s) ran, below the --min-tests floor of %s.\n' \
    "$TOTAL_TESTS" "$MIN_TESTS"
  printf '         A suite has been emptied or silently filtered out.\n'
  if [[ "$FAILURES" -eq 0 ]]; then
    exit 2
  fi
  exit "$FAILURES"
fi

# ---- check 4: every --expect-test target actually executed -------------------
for want in ${EXPECT_TESTS[@]+"${EXPECT_TESTS[@]}"}; do
  # A binary counts as "expected" only if it reported >= 1 executed test: a
  # binary that merely appears in the log while running 0 tests is not evidence.
  if awk -F'\t' -v want="$want" '$3 + 0 >= 1 && index($1, want) > 0 { found = 1 } END { exit !found }' "$TSV"; then
    :
  elif [[ -s "$NAMES" ]] && grep -qF -- "$want" "$NAMES"; then
    :
  else
    printf '\n'
    printf ' RESULT: FAIL — expected test target %s did not run.\n' "$want"
    printf '         It matched no test binary that executed a test, and no\n'
    printf '         executed test name. If the test was renamed, this gate\n'
    printf '         would otherwise pass while testing nothing.\n'
    if [[ "$FAILURES" -eq 0 ]]; then
      exit 4
    fi
    exit "$FAILURES"
  fi
  printf ' expect OK: %s\n' "$want"
done

if [[ "$FAILURES" -ne 0 ]]; then
  printf '\n'
  printf ' log: %s\n' "$LOG_FILE"
  exit "$FAILURES"
fi

printf '\n'
printf ' RESULT: PASS — %s test(s) across %s binary/binaries, cargo exit 0, floor %s satisfied.\n' \
  "$TOTAL_TESTS" "$N_BIN" "$MIN_TESTS"
printf ' log: %s\n' "$LOG_FILE"
printf '\n'
exit 0
