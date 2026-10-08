"""AEM ECO v0.1: pure, offline decision shadow; NEVER authorizes payments.

No network, wallet, token minting, trading, system changes or subprocesses.
An observation is untrusted; real permissions MUST remain in existing Rust gates.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
import math
import time
from pathlib import Path
from typing import Any

HARD_C = 75.0
RESUME_C = 70.0
MAX_AGE_S = 30.0
COLD_MAX_S = 3600


@dataclass(frozen=True)
class Observation:
    sensor_unix: float
    package_c: float | None
    mupp_unix: float
    mupp_allow: bool
    no_edge: bool = False
    alternative_class_supported: bool = False
    paid_job_observed: bool = False
    candidate_observed: bool = False

    @classmethod
    def parse(cls, raw: dict[str, Any]) -> "Observation":
        for key in ("mupp_allow", "no_edge", "alternative_class_supported",
                    "paid_job_observed", "candidate_observed"):
            if key in raw and type(raw[key]) is not bool:
                raise ValueError(f"{key}: expected JSON boolean")
        if raw.get("no_edge") and raw.get("candidate_observed"):
            raise ValueError("no_edge and candidate_observed are mutually exclusive")
        for key in ("sensor_unix", "mupp_unix"):
            if key not in raw or type(raw[key]) not in (int, float):
                raise ValueError(f"{key}: expected number")
        if "package_c" in raw and raw["package_c"] is not None:
            if type(raw["package_c"]) not in (int, float):
                raise ValueError("package_c: expected number or null")
        return cls(**raw)


@dataclass(frozen=True)
class ControllerMemory:
    # Fail closed on first start, until a valid <=70 C sample is observed.
    thermal_latched: bool = True
    no_edge_streak: int = 0

    @classmethod
    def parse(cls, raw: dict[str, Any]) -> "ControllerMemory":
        if type(raw.get("thermal_latched", True)) is not bool:
            raise ValueError("thermal_latched: expected boolean")
        streak = raw.get("no_edge_streak", 0)
        if type(streak) is not int or streak < 0:
            raise ValueError("no_edge_streak: expected nonnegative integer")
        return cls(**raw)


@dataclass(frozen=True)
class Decision:
    state: str
    reason: str
    next_check_seconds: int
    next_memory: ControllerMemory
    # All are ALWAYS false. The real Risk Kernel is outside this module.
    trade_authorized: bool = False
    mint_authorized: bool = False
    reinvestment_authorized: bool = False


def evaluate(
    observation: Observation,
    previous: ControllerMemory,
    now_unix: float,
) -> Decision:
    """Recommend a low-power step without granting economic authority."""
    def result(state: str, reason: str, delay: int, latch: bool,
               streak: int) -> Decision:
        return Decision(state, reason, delay, ControllerMemory(latch, streak))

    if not isinstance(now_unix, (int, float)) or not math.isfinite(now_unix):
        return result("SENSOR_LOCK", "invalid_clock", 120, True, previous.no_edge_streak)

    for name, observed_at in (("sensor", observation.sensor_unix),
                              ("mupp", observation.mupp_unix)):
        if not math.isfinite(observed_at):
            return result("SENSOR_LOCK", f"{name}_invalid_time", 120, True, previous.no_edge_streak)
        age = now_unix - observed_at
        if age < 0 or age > MAX_AGE_S:
            return result("SENSOR_LOCK", f"{name}_future_or_stale", 120, True, previous.no_edge_streak)

    temperature = observation.package_c
    if temperature is None or not math.isfinite(temperature) or temperature < -40 or temperature > 130:
        return result("SENSOR_LOCK", "missing_or_invalid_temperature", 120, True,
                      previous.no_edge_streak)

    latched = temperature >= HARD_C or (previous.thermal_latched and temperature > RESUME_C)
    if latched:
        return result("THERMAL_LOCK", "temperature_or_cooldown", 120, True, previous.no_edge_streak)
    if not observation.mupp_allow:
        return result("MUPP_LOCK", "independent_mupp_gate_denied", 120, False,
                      previous.no_edge_streak)

    if observation.no_edge:
        streak = min(previous.no_edge_streak + 1, 1000000)
        delay = min(COLD_MAX_S, 60 * (2 ** min(streak - 1, 6)))
        if observation.alternative_class_supported:
            return result("ROTATE_CLASS", "no_edge_rotate_only_supported_class",
                          delay, False, streak)
        return result("COLD_DISCOVERY", "no_edge_no_supported_alternative",
                      delay, False, streak)

    if observation.paid_job_observed:
        return result("VERIFY_JOB_SHADOW", "requires_external_settlement_verification",
                      60, False, 0)
    if observation.candidate_observed:
        return result("SIMULATE_CANDIDATE_SHADOW", "no_execution_authority",
                      60, False, 0)
    return result("LOW_POWER_DISCOVERY", "only_budgeted_supported_scans",
                  120, False, 0)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observation", required=True, type=Path)
    parser.add_argument("--memory", type=Path)
    args = parser.parse_args()
    try:
        obs = Observation.parse(json.loads(args.observation.read_text()))
        mem = (ControllerMemory.parse(json.loads(args.memory.read_text()))
               if args.memory else ControllerMemory())
        dec = evaluate(obs, mem, time.time())
        print(json.dumps(asdict(dec), ensure_ascii=False, sort_keys=True))
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        parser.error(f"invalid observation or memory: {exc}")


if __name__ == "__main__":
    main()
