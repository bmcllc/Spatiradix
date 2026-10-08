#!/usr/bin/env python3
"""Thermally guarded, CPU-duty-limited build for the CQR Rust worker.

On refusal or alarm, terminate the entire private build process group.
Does NOT fake the S1-MUPP state or execute the CQR job itself.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
MAX_C = 75.0
START_MAX_C = 70.0
MAX_RUNTIME_SECONDS = 900
# A longer deadline is safe only because the thermal ceiling remains unchanged.
# Increase useful compilation time when sensors prove adequate cooling.
THERMAL_PAUSE_C = 70.0
THERMAL_RESUME_C = 65.0
LOGFILE = Path("/tmp/mycelium-cqr-guarded-build.log")


def cpu_thermal_paths() -> list[Path]:
    hwmon = Path("/sys/class/hwmon")
    matches: list[Path] = []
    for entry in sorted(hwmon.glob("hwmon*")):
        try:
            if (entry / "name").read_text().strip() == "coretemp":
                matches += sorted(entry.glob("temp*_input"))
        except OSError:
            raise RuntimeError("cannot read hwmon identity")
    if not matches:
        raise RuntimeError("CPU coretemp sensors missing")
    return matches


def temperature(paths: list[Path]) -> float:
    # Required thermal zones + hwmon CPU. Any unreadable sensor aborts.
    all_paths = list(paths) + sorted(Path("/sys/class/thermal").glob("thermal_zone*/temp"))
    if not all_paths:
        raise RuntimeError("no hardware thermal sensors")
    readings = []
    for path in all_paths:
        try:
            value = float(path.read_text().strip()) / 1000.0
        except (OSError, ValueError) as exc:
            raise RuntimeError("hardware sensor unavailable") from exc
        if not -20 <= value <= 150 or value != value:
            raise RuntimeError("invalid hardware temperature")
        readings.append(value)
    return max(readings)


def duty_cycle(celsius: float, cooling_pause: bool) -> tuple[float, float]:
    """Return bounded active/idle windows, never allowing work in cooldown."""
    if cooling_pause or celsius >= THERMAL_PAUSE_C:
        return (0.0, 0.25)
    if celsius >= 66.0:
        return (0.06, 0.24)
    if celsius >= 62.0:
        return (0.10, 0.16)
    # ~60% CPU time at low temperatures; original was only ~18%.
    return (0.12, 0.08)


def terminate_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGCONT)
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=2)


def run() -> int:
    sensors = cpu_thermal_paths()
    initial = temperature(sensors)
    print(f"initial_temperature_c={initial:.1f}", flush=True)
    if initial > START_MAX_C:
        print("REFUSED: must start from <=70C; build not launched", flush=True)
        return 3
    if not hasattr(os, "sched_getaffinity"):
        print("REFUSED: cannot bound CPU affinity", flush=True)
        return 3
    allowed_cpus = os.sched_getaffinity(0)
    if not allowed_cpus:
        print("REFUSED: no permitted CPU", flush=True)
        return 3
    chosen_cpu = min(allowed_cpus)
    command = [
        "taskset", "-c", str(chosen_cpu),
        "nice", "-n", "19",
        "cargo", "build", "--offline",
        "-p", "mycelium-economy", "--bin", "mycelium-cqr-worker", "-j", "1",
    ]
    env = dict(os.environ, CARGO_BUILD_JOBS="1", CARGO_TERM_COLOR="never")
    start = time.monotonic()
    peak = initial
    status = "unknown"
    rc = 3
    cooling_pause = False
    next_progress = start + 30.0
    with LOGFILE.open("w") as log:
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            env=env,
        )
        try:
            while True:
                live = temperature(sensors)
                peak = max(peak, live)
                if live >= MAX_C:
                    status = "thermal_abort"
                    rc = 3
                    break
                if time.monotonic() - start > MAX_RUNTIME_SECONDS:
                    status = "time_budget_abort"
                    rc = 3
                    break
                done = process.poll()
                if done is not None:
                    status = "success" if done == 0 else "compilation_failed"
                    rc = done
                    break
                if live >= THERMAL_PAUSE_C and not cooling_pause:
                    cooling_pause = True
                    print(f"thermal_pause_start_c={live:.1f}", flush=True)
                elif cooling_pause and live <= THERMAL_RESUME_C:
                    cooling_pause = False
                    print(f"thermal_pause_end_c={live:.1f}", flush=True)

                active_seconds, idle_seconds = duty_cycle(live, cooling_pause)
                if active_seconds:
                    time.sleep(active_seconds)
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGSTOP)
                    except ProcessLookupError:
                        pass
                    # Idle-time watchdog keeps running even if Cargo is stopped.
                    until = time.monotonic() + idle_seconds
                    while time.monotonic() < until:
                        time.sleep(min(0.05, max(0.0, until - time.monotonic())))
                        live = temperature(sensors)
                        peak = max(peak, live)
                        if live >= MAX_C:
                            status = "thermal_abort"
                            rc = 3
                            break
                        if time.monotonic() - start > MAX_RUNTIME_SECONDS:
                            status = "time_budget_abort"
                            rc = 3
                            break
                    if status in ("thermal_abort", "time_budget_abort"):
                        break
                    if time.monotonic() >= next_progress:
                        print(f"build_running_s={time.monotonic()-start:.0f} "
                              f"current_c={live:.1f} peak_c={peak:.1f} "
                              f"cooling_pause={cooling_pause}", flush=True)
                        next_progress = time.monotonic() + 30.0
                    # Re-evaluate cooling policy before allowing more work.
                    if live >= THERMAL_PAUSE_C:
                        cooling_pause = True
                    elif live <= THERMAL_RESUME_C:
                        cooling_pause = False
                    if process.poll() is None and not cooling_pause:
                        try:
                            os.killpg(process.pid, signal.SIGCONT)
                        except ProcessLookupError:
                            pass
        except (OSError, ValueError, RuntimeError, KeyboardInterrupt) as exc:
            status = "sensor_or_supervisor_error"
            rc = 3
            print(f"guard_error={type(exc).__name__}", flush=True)
        finally:
            if process.poll() is None:
                terminate_group(process)
            print(
                f"build_status={status} build_exit={rc} "
                f"peak_temperature_c={peak:.1f} "
                f"elapsed_s={time.monotonic() - start:.1f} "
                f"log={LOGFILE}",
                flush=True,
            )
    return rc


if __name__ == "__main__":
    try:
        raise SystemExit(run())
    except (RuntimeError, OSError, ValueError) as exc:
        print(f"REFUSED: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        raise SystemExit(3)
