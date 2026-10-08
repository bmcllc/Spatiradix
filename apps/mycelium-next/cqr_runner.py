"""Strict local subprocess adapter for the native CQR-C0 worker.

Only an explicit queued CQR job may call this adapter. Does not grant S1,
financial, signer, token or network authority. Native worker rechecks real
MUPP and hardware sensors independently and enforces rlimits on Linux.
"""
import json
import math
from pathlib import Path
import re
import subprocess

MAX_REQUEST = 65_536
MAX_OUTPUT = 262_144
HEX64 = re.compile(r"^[0-9a-f]{64}$")
WORKER = Path(__file__).resolve().parents[2] / "target/debug/mycelium-cqr-worker"


def validate_request(value):
    if type(value) is not dict or set(value) != {"spec", "initial_state"}:
        raise ValueError("CQR request must be spec + initial_state")
    spec, initial = value["spec"], value["initial_state"]
    if type(spec) is not dict or type(initial) is not dict:
        raise ValueError("invalid CQR spec or phase space")
    if set(initial) != {"q", "p"}:
        raise ValueError("invalid phase space keys")
    if (type(spec.get("schema_version")) is not int
            or spec["schema_version"] != 1
            or spec.get("compute_level") != "c0_classical_symplectic"
            or spec.get("model_id") != "coupled_oscillators_64"
            or spec.get("model_version") != "1.0.0"
            or spec.get("integrator_spec") != "velocity_verlet"
            or spec.get("precision_policy") != "float64_strict"
            or spec.get("expected_observables") != ["energy"]
            or spec.get("validation_suite") != ["symplectic_conservation"]):
        raise ValueError("unsupported CQR implementation/validation contract")
    classical = spec.get("classical_spec")
    budget = spec.get("resource_budget")
    if type(classical) is not dict or type(budget) is not dict:
        raise ValueError("missing classical spec or resource budget")
    if type(classical.get("oscillator_count")) is not int or classical["oscillator_count"] != 64:
        raise ValueError("only 64 oscillators supported")
    if classical.get("periodic_boundary") is not True:
        raise ValueError("non-periodic CQR cannot satisfy this validation protocol")
    for key in ("mass", "spring_constant"):
        value = classical.get(key)
        if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
            raise ValueError(f"invalid positive CQR classical parameter {key}")
    for key in ("q", "p"):
        arr = initial[key]
        if (type(arr) is not list or len(arr) != 64
                or any(type(x) not in (int, float) or not math.isfinite(x) for x in arr)):
            raise ValueError("phase-space vectors must contain 64 finite numbers")
    for name, lo, hi in (("step_count", 1, 5000),):
        v = spec.get(name)
        if type(v) is not int or not lo <= v <= hi:
            raise ValueError("invalid bounded CQR step_count")
    dt = spec.get("time_step")
    if type(dt) not in (float, int) or not math.isfinite(dt) or not 0 < dt <= 1:
        raise ValueError("invalid CQR time step")
    for field, lo, hi in (("max_cpu_time_ms", 1, 10000),
                          ("max_wall_time_ms", 1, 30000),
                          ("max_memory_bytes", 128 * 1024 * 1024, 512 * 1024 * 1024),
                          ("thermal_ceiling_celsius", 70, 75)):
        v = budget.get(field)
        if type(v) is not int or not lo <= v <= hi:
            raise ValueError(f"invalid CQR resource limit {field}")
    job_id = spec.get("job_id")
    if type(job_id) is not str or not 1 <= len(job_id) <= 128:
        raise ValueError("invalid CQR job ID")
    initial_hash = spec.get("initial_state_hash")
    if type(initial_hash) is not str or not HEX64.fullmatch(initial_hash):
        raise ValueError("invalid CQR input-state hash")
    try:
        encoded = json.dumps(value, sort_keys=True, allow_nan=False).encode()
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid CQR JSON") from exc
    if len(encoded) > MAX_REQUEST:
        raise ValueError("CQR request exceeds native worker input bound")
    return encoded


def run_cqr(value, worker=WORKER):
    encoded = validate_request(value)
    binary = Path(worker)
    if not binary.is_file() or not binary.stat().st_mode & 0o111:
        raise OSError("compiled CQR native worker unavailable")
    limit_ms = value["spec"]["resource_budget"]["max_wall_time_ms"]
    # Two reproducibility runs + one primary execution, independently bounded
    # in native Rust; the OS subprocess timeout is an overall ceiling.
    timeout = min(100, max(10, (3 * limit_ms / 1000) + 5))
    try:
        proc = subprocess.run(
            [str(binary)],
            input=encoded,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
            start_new_session=True,
        )
    except subprocess.TimeoutExpired as exc:
        # subprocess.run kills/reaps the child before raising. Let the normal
        # queue retry policy account for this as a bounded unavailable worker.
        raise OSError("native CQR worker exceeded its wall-time budget") from exc
    if proc.returncode:
        # Do not record a potentially attacker-controlled stderr or private data.
        raise ValueError("CQR native worker refused execution")
    if len(proc.stdout) > MAX_OUTPUT:
        raise ValueError("CQR native result exceeds output bound")
    try:
        result = json.loads(proc.stdout)
    except (UnicodeError, ValueError) as exc:
        raise ValueError("invalid CQR native JSON result") from exc
    if type(result) is not dict:
        raise ValueError("invalid native result type")
    report = result.get("validation_report")
    native = result.get("result")
    expected = "LOCAL_CQR_C0_SCIENTIFIC_VALIDATION_NOT_EXTERNAL_SETTLEMENT"
    if (result.get("scope") != expected
            or result.get("job_id") != value["spec"]["job_id"]
            or type(result.get("validation_passed")) is not bool
            or not result["validation_passed"]
            or type(result.get("received_revenue")) is not bool
            or result["received_revenue"]
            or result.get("verified_nev") is not None
            or result.get("wallet_signing") is not False
            or result.get("onchain_execution") is not False
            or type(report) is not dict or type(native) is not dict):
        raise ValueError("CQR worker did not return a valid scientific result")
    for field in ("numerical_valid", "physical_known_answer_valid", "bitwise_reproducible"):
        if report.get(field) is not True:
            raise ValueError("CQR independent validation failed")
    if (native.get("validation_passed") is not True
            or native.get("job_id") != result["job_id"]
            or native.get("result_digest") != result.get("result_digest")
            or native.get("job_hash") != result.get("job_hash")):
        raise ValueError("CQR native result binding failed")
    for field in ("job_hash", "result_digest"):
        v = result[field]
        if type(v) is not str or not HEX64.fullmatch(v):
            raise ValueError("invalid CQR commitment")
    thermal = result.get("maximum_thermal_c")
    if type(thermal) not in (int, float) or not math.isfinite(thermal) or thermal >= 75:
        raise ValueError("CQR thermal evidence invalid")
    return result
