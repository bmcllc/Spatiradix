#!/usr/bin/env python3
"""Read-only thermal baseline sampler for Mycelium Next.

NO benchmark, subprocess, clock modification, root actions or permission grant.
This diagnostic is never valid as S1-MUPP authorization or paid-work proof.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import statistics
import time

from mycelium_next import temperatures


def read_optional_number(path: Path, divisor: float = 1.0):
    try:
        value = float(path.read_text().strip()) / divisor
    except (OSError, ValueError):
        return None
    return value if math.isfinite(value) else None


def cpu_package():
    """Require a named coretemp package sensor; never substitute an ACPI value."""
    root = Path("/sys/class/hwmon")
    packages = []
    errors = []
    try:
        entries = sorted(root.glob("hwmon*"))
    except OSError:
        return None, ["hwmon_enumeration_failed"]
    for directory in entries:
        try:
            name = (directory / "name").read_text().strip()
        except OSError:
            errors.append(str(directory / "name"))
            continue
        if name != "coretemp":
            continue
        value = read_optional_number(directory / "temp1_input", 1000.0)
        if value is None or not 0 <= value <= 150:
            errors.append(str(directory / "temp1_input"))
        else:
            packages.append(value)
    if not packages:
        errors.append("cpu_coretemp_package_missing")
    return max(packages) if packages else None, errors


def snapshot(clock=time.time):
    observed_at = clock()
    status = temperatures()
    maximum = None
    if status["samples"] and not status["errors"]:
        maximum = max(sample["celsius"] for sample in status["samples"])
    package, package_errors = cpu_package()
    freq = read_optional_number(
        Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq"), 1000.0
    )
    # Frequency only represents CPU0, not all 12 logical CPUs.
    return {
        "time_unix_s": observed_at,
        "cpu_package_c": package,
        "maximum_sensor_c": maximum,
        "cpu0_freq_mhz": freq,
        "sensor_error_count": len(status["errors"]) + len(package_errors),
        "sensor_valid": not status["errors"] and not package_errors
                        and maximum is not None and package is not None,
    }


def series(count=24, interval_s=0.25, clock=time.time, sleeper=time.sleep):
    if type(count) is not int or not 1 <= count <= 80:
        raise ValueError("count outside diagnostic bound [1,80]")
    if type(interval_s) not in (float, int) or not 0.2 <= interval_s <= 2:
        raise ValueError("interval outside diagnostic bound [0.2,2] seconds")
    results = []
    for i in range(count):
        results.append(snapshot(clock=clock))
        if i + 1 < count:
            sleeper(interval_s)
    temps = [x["cpu_package_c"] for x in results if x["cpu_package_c"] is not None]
    full_temps = [x["maximum_sensor_c"] for x in results
                  if x["maximum_sensor_c"] is not None]
    frequencies = [x["cpu0_freq_mhz"] for x in results
                   if x["cpu0_freq_mhz"] is not None]
    return {
        "schema_version": 1,
        "mode": "READ_ONLY_THERMAL_DIAGNOSTIC_NOT_S1_OR_EXECUTION_AUTHORITY",
        "captured_at": datetime.fromtimestamp(
            results[0]["time_unix_s"], tz=timezone.utc).isoformat(),
        "sample_count": count,
        "interval_seconds": interval_s,
        "all_sensors_valid": all(x["sensor_valid"] for x in results),
        "cpu_package_min_c": min(temps) if temps else None,
        "cpu_package_median_c": statistics.median(temps) if temps else None,
        "cpu_package_max_c": max(temps) if temps else None,
        "all_sensor_max_c": max(full_temps) if full_temps else None,
        "cpu0_freq_min_mhz": min(frequencies) if frequencies else None,
        "cpu0_freq_max_mhz": max(frequencies) if frequencies else None,
        "over_75c_samples": sum(x["maximum_sensor_c"] is not None
                                and x["maximum_sensor_c"] >= 75 for x in results),
        "samples": results,
        "cqr_executed": False,
        "verified_nev": None,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=24)
    parser.add_argument("--interval", type=float, default=0.25)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = series(args.samples, args.interval)
    content = json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n"
    if args.output is None:
        print(content, end="")
    else:
        # Evidence path is caller-selected; never touch any device controls.
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(content)
        print(f"wrote={args.output}")
        print(
            f"cpu_package_min_c={report['cpu_package_min_c']} "
            f"cpu_package_max_c={report['cpu_package_max_c']} "
            f"over_75c_samples={report['over_75c_samples']} "
            f"all_sensors_valid={report['all_sensors_valid']}"
        )


if __name__ == "__main__":
    main()
