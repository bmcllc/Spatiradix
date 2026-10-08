#!/usr/bin/env bash
# Temporarily turn off Intel Turbo Boost for the thermally guarded CQR-C0 build.
# REQUIRES interactive sudo authorization in the user's own terminal.
# Do NOT run this script with sudo; only the sysfs write needs root.
set -Eeuo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
control="/sys/devices/system/cpu/intel_pstate/no_turbo"
builder="$root/apps/mycelium-next/guarded_cqr_build.py"

check() {
  if [[ ! -r "$control" ]]; then
    echo "REFUSED: Intel P-state Turbo control not readable" >&2
    return 3
  fi
  if [[ ! -f "$builder" ]]; then
    echo "REFUSED: guarded build program missing" >&2
    return 3
  fi
  for binary in sudo python3 taskset nice cargo sensors; do
    if ! command -v "$binary" >/dev/null 2>&1; then
      echo "REFUSED: missing dependency: $binary" >&2
      return 3
    fi
  done
  local previous
  previous="$(<"$control")"
  case "$previous" in
    0|1) echo "control=$control current_no_turbo=$previous guarded_builder=$builder" ;;
    *) echo "REFUSED: unexpected Intel Turbo control value" >&2; return 3 ;;
  esac
}

if [[ "${1:-}" == "--check" && "$#" == 1 ]]; then
  check
  exit $?
fi
if [[ "$#" != 0 ]]; then
  echo "Usage: bash apps/mycelium-next/build_cqr_turbo_off.sh [--check]" >&2
  exit 2
fi
if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
  echo "REFUSED: start as normal desktop user, NOT with sudo" >&2
  exit 3
fi
check

# This is the user's interactive terminal. Never request a password over
# Remote Desktop Commander, store credentials or relax sysfs ownership.
if ! sudo -v; then
  echo "REFUSED: no administrator authorization" >&2
  exit 3
fi

previous="$(<"$control")"
if [[ "$previous" != 0 && "$previous" != 1 ]]; then
  echo "REFUSED: invalid original no_turbo state" >&2
  exit 3
fi

restore_turbo() {
  local observed
  observed="$(cat "$control" 2>/dev/null || echo unreadable)"
  if [[ "$observed" == "$previous" ]]; then
    echo "RESTORED: Intel no_turbo=$previous (unchanged or already restored)"
    return 0
  fi

  # Within the normal 150-second build timeout the authenticated sudo ticket
  # should still be valid. Attempt a normal interactive fallback if it isn't.
  if printf '%s\n' "$previous" | sudo -n tee "$control" >/dev/null; then
    :
  else
    echo "WARNING: sudo ticket expired. Reauthorize to restore Turbo." >&2
    if ! printf '%s\n' "$previous" | sudo tee "$control" >/dev/null; then
      echo "CRITICAL: Restore Intel Turbo manually using:" >&2
      echo "  echo '$previous' | sudo tee '$control'" >&2
      return 3
    fi
  fi

  observed="$(cat "$control" 2>/dev/null || echo unreadable)"
  if [[ "$observed" != "$previous" ]]; then
    echo "CRITICAL: no_turbo restoration could not be verified" >&2
    return 3
  fi
  echo "RESTORED: Intel no_turbo=$previous"
}

# Install traps BEFORE touching the CPU governor state.
on_exit() {
  local exit_code="$?"
  trap - EXIT
  if ! restore_turbo; then
    echo "CRITICAL: restoration failed; original status=$exit_code" >&2
    exit 4
  fi
  exit "$exit_code"
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

if [[ "$previous" == 0 ]]; then
  if ! printf '1\n' | sudo -n tee "$control" >/dev/null; then
    echo "REFUSED: could not disable Intel Turbo" >&2
    exit 3
  fi
fi

if [[ "$(<"$control")" != 1 ]]; then
  echo "REFUSED: no_turbo=1 was not verified" >&2
  exit 3
fi

echo "TEMPORARY: Intel Turbo disabled (no_turbo=1); original=$previous"
echo "The thermal guard requires <=70C start and stops at >=75C."
cd -- "$root"
if python3 -u "$builder"; then
  build_rc=0
else
  build_rc=$?
fi
echo "GUARDED_BUILD_EXIT=$build_rc"
exit "$build_rc"
