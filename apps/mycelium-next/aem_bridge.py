"""Adapt existing Mycelium Next thermal/MUPP gate into AEM advisory only.

Never derives finance authority and never starts work. The original Engine.gate()
is the sole execution authorization for this Python prototype.
"""
from __future__ import annotations

from dataclasses import asdict
import math

from aem_shadow import ControllerMemory, Decision, Observation, evaluate


def denied(state: str, reason: str, memory: ControllerMemory,
           thermal_latch: bool = True) -> Decision:
    """Conservative advice when existing gate or provenance cannot be verified."""
    return Decision(
        state=state,
        reason=reason,
        next_check_seconds=120,
        next_memory=ControllerMemory(
            thermal_latched=thermal_latch,
            no_edge_streak=memory.no_edge_streak,
        ),
    )


def decide_from_gate(gate: dict, memory: ControllerMemory,
                     now_unix: float) -> Decision:
    """Read the already-evaluated gate; never promote an unsupported signal.

    No NO_EDGE or NEV input exists on this bridge yet. Rust's verified_view and
    discovery machine remain their only eventual sources of authority.
    """
    if not isinstance(gate, dict) or type(gate.get("allowed")) is not bool:
        return denied("SENSOR_LOCK", "malformed_existing_gate", memory)
    if type(now_unix) not in (int, float) or not math.isfinite(now_unix):
        return denied("SENSOR_LOCK", "invalid_clock", memory)
    if not gate["allowed"]:
        reason = gate.get("reason")
        if reason == "cooldown":
            return denied("THERMAL_LOCK", "existing_thermal_gate_denied", memory)
        if reason == "unknown_or_invalid_sensor":
            return denied("SENSOR_LOCK", "existing_sensor_gate_denied", memory)
        return denied("MUPP_LOCK", "existing_s1_mupp_gate_denied", memory)

    # Re-verify that this advice comes from a recently evaluated sensor report
    # and valid MUPP provenance. Do not fabricate timestamps or allow flags.
    try:
        provenance = gate["provenance"]
        s1 = gate["s1_mupp"]
        observed_at = provenance["sampled_at_unix_s"]
        mupp_provenance = s1["provenance"]
        mupp_at = mupp_provenance["timestamp_unix"]
        max_c = gate["maximum_celsius"]
        if type(s1.get("allowed")) is not bool or not s1["allowed"]:
            return denied("MUPP_LOCK", "mupp_not_allowed", memory)
        observation = Observation.parse({
            "sensor_unix": observed_at,
            "package_c": max_c,
            "mupp_unix": mupp_at,
            "mupp_allow": s1["allowed"],
        })
        decision = evaluate(observation, memory, now_unix)
        if not gate["allowed"]:
            return denied("MUPP_LOCK", "existing_gate_denied", memory)
        return decision
    except (KeyError, TypeError, ValueError, OverflowError, AttributeError):
        return denied("SENSOR_LOCK", "missing_or_invalid_gate_provenance", memory)


def public_advice(decision: Decision, sampled_at_unix: float) -> dict:
    """Explicitly identify advice as SHADOW; financial permissions always false."""
    result = asdict(decision)
    result.pop("next_memory", None)
    return {
        "scope": "AEM_ECO_SHADOW_NO_EXECUTION_AUTHORITY",
        "observed_unix_s": sampled_at_unix,
        "decision": result,
        "evidence": {
            "no_edge": "not_connected_to_discovery",
            "nev": "not_connected_to_verified_view",
            "paid_demand": None,
            "realized_revenue": None,
        },
    }
