"""AEM ECO v0.2: offline quote admission, never execution or VerifiedNev.

All declarations are untrusted forecasts, including funding and adapter flags.
No network, wallet, subprocess, persistence, measurement or budget reservation.
Costs and payment use integer micro-USDC; currency conversion is outside scope.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timezone
import json
import math
from pathlib import Path
import time
from typing import Any

from aem_shadow import ControllerMemory, Decision, MAX_AGE_S, Observation, evaluate

MAX_INPUT_BYTES = 64 * 1024
MAX_MONEY = (1 << 63) - 1
MAX_CPU_MS = 10_000
MAX_WALL_MS = 30_000


def nonnegative_int(name: str, value: Any) -> None:
    if type(value) is not int or not 0 <= value <= MAX_MONEY:
        raise ValueError(f"{name}: expected nonnegative bounded integer")


def timestamp(name: str, value: Any) -> None:
    if type(value) not in (int, float) or not 0 <= value <= 253402300799 or not math.isfinite(value):
        raise ValueError(f"{name}: expected finite Unix timestamp")


def energy_cost_upper_micros(joules_upper: int, tariff_micros_per_kwh: int) -> int:
    """Round UP a supplied energy bound, using an explicitly same-currency tariff.

    This does not measure watts/joules, obtain a tariff or convert BRL to USDC.
    A temperature sample is not an energy bound.
    """
    nonnegative_int("joules_upper", joules_upper)
    nonnegative_int("tariff_micros_per_kwh", tariff_micros_per_kwh)
    return (joules_upper * tariff_micros_per_kwh + 3_600_000 - 1) // 3_600_000


@dataclass(frozen=True)
class Costs:
    # Explicit zero means declared zero; null means unknown and blocks admission.
    energy: int | None
    settlement: int | None
    rpc: int | None
    storage: int | None
    wear: int | None

    def __post_init__(self) -> None:
        for name, value in asdict(self).items():
            if value is not None:
                nonnegative_int(name, value)


@dataclass(frozen=True)
class Quote:
    job_id: str
    currency: str
    expires_unix: float
    payment_lower_micros: int | None
    costs_upper_micros: Costs
    external_payer_declared: bool
    funding_evidence_declared: bool
    adapter_implemented_declared: bool
    gpu_required: bool
    total_cpu_ms: int
    total_wall_ms: int

    def __post_init__(self) -> None:
        if type(self.job_id) is not str or not self.job_id.strip() or len(self.job_id) > 128:
            raise ValueError("job_id: expected nonempty identifier of at most 128 characters")
        if self.currency != "USDC":
            raise ValueError("currency: only explicit micro-USDC quotes are supported")
        timestamp("expires_unix", self.expires_unix)
        if self.payment_lower_micros is not None:
            nonnegative_int("payment_lower_micros", self.payment_lower_micros)
        if type(self.costs_upper_micros) is not Costs:
            raise ValueError("costs_upper_micros: expected all five cost components")
        for name in ("external_payer_declared", "funding_evidence_declared",
                     "adapter_implemented_declared", "gpu_required"):
            if type(getattr(self, name)) is not bool:
                raise ValueError(f"{name}: expected boolean")
        for name in ("total_cpu_ms", "total_wall_ms"):
            nonnegative_int(name, getattr(self, name))
            if getattr(self, name) == 0:
                raise ValueError(f"{name}: expected positive resource estimate")

    @classmethod
    def parse(cls, raw: dict[str, Any]) -> "Quote":
        if type(raw) is not dict:
            raise ValueError("quote: expected object")
        values = dict(raw)
        costs = values.get("costs_upper_micros")
        if type(costs) is not dict:
            raise ValueError("costs_upper_micros: expected object")
        values["costs_upper_micros"] = Costs(**costs)
        return cls(**values)


@dataclass(frozen=True)
class Policy:
    min_profit_micros: int
    risk_reserve_micros: int
    max_job_exposure_micros: int
    daily_exposure_limit_micros: int
    max_cpu_ms: int
    max_wall_ms: int

    def __post_init__(self) -> None:
        for name, value in asdict(self).items():
            nonnegative_int(name, value)
        if self.min_profit_micros == 0:
            raise ValueError("min_profit_micros must be positive; NO_EDGE cannot lower it")
        if not 0 < self.max_cpu_ms <= MAX_CPU_MS or not 0 < self.max_wall_ms <= MAX_WALL_MS:
            raise ValueError("resource limits exceed the offline profile (10 CPU s / 30 wall s)")


@dataclass(frozen=True)
class BudgetSnapshot:
    sampled_unix: float
    day_utc: str
    spent_micros: int
    reserved_micros: int

    def __post_init__(self) -> None:
        timestamp("sampled_unix", self.sampled_unix)
        if type(self.day_utc) is not str or date.fromisoformat(self.day_utc).isoformat() != self.day_utc:
            raise ValueError("day_utc: expected YYYY-MM-DD")
        nonnegative_int("spent_micros", self.spent_micros)
        nonnegative_int("reserved_micros", self.reserved_micros)


@dataclass(frozen=True)
class Forecast:
    state: str
    reason: str
    gate_state: str
    cost_upper_micros: int | None = None
    net_lower_micros: int | None = None
    required_reservation_micros: int | None = None
    scope: str = field(default="SHADOW_QUOTE", init=False)
    verified_nev: None = field(default=None, init=False)
    execution_authorized: bool = field(default=False, init=False)
    trade_authorized: bool = field(default=False, init=False)
    mint_authorized: bool = field(default=False, init=False)
    reinvestment_authorized: bool = field(default=False, init=False)


def evaluate_quote(quote: Quote, policy: Policy, budget: BudgetSnapshot,
                   gate: Decision, now_unix: float) -> Forecast:
    """Forecast one job; real gates must independently verify every declaration.

    The existing AEM shadow supplies thermal/MUPP advice and NO_EDGE backoff.
    This function cannot mutate those gates, reserve a budget or authorize a job.
    """
    timestamp("now_unix", now_unix)

    def result(state: str, reason: str, cost: int | None = None,
               net: int | None = None, reserve: int | None = None) -> Forecast:
        return Forecast(state, reason, gate.state, cost, net, reserve)

    if gate.state != "VERIFY_JOB_SHADOW":
        return result("GATE_BLOCKED", "existing_thermal_mupp_or_discovery_advice_blocks_job")
    if now_unix >= quote.expires_unix:
        return result("EXPIRED_QUOTE", "request_fresh_payment_and_cost_bounds")
    age = now_unix - budget.sampled_unix
    day_utc = datetime.fromtimestamp(now_unix, timezone.utc).date().isoformat()
    if not 0 <= age <= MAX_AGE_S or budget.day_utc != day_utc:
        return result("BUDGET_LOCK", "budget_future_stale_or_different_utc_day")
    if not quote.adapter_implemented_declared:
        return result("UNSUPPORTED_SERVICE", "do_not_invent_an_executable_adapter")
    if quote.gpu_required or quote.total_cpu_ms > policy.max_cpu_ms or quote.total_wall_ms > policy.max_wall_ms:
        return result("RESOURCE_LOCK", "gpu_off_and_bounded_cpu_wall_time_required")
    if not quote.external_payer_declared:
        return result("INTERNAL_WORK", "internal_tokens_and_self_payments_are_not_external_demand")
    if not quote.funding_evidence_declared:
        return result("UNFUNDED_JOB", "request_independent_funding_and_acceptance_evidence")
    if quote.payment_lower_micros is None:
        return result("UNPRICED_JOB", "payment_bound_unknown")
    costs = asdict(quote.costs_upper_micros)
    missing = [name for name, value in costs.items() if value is None]
    if missing:
        return result("MEASURE_COST_SHADOW", "unknown_costs:" + ",".join(missing))
    cost = sum(costs.values())
    reserve = cost + policy.risk_reserve_micros
    net = quote.payment_lower_micros - reserve
    if net < policy.min_profit_micros:
        return result("NO_EDGE_QUOTE", "forecast_below_fixed_profit_floor", cost, net, reserve)
    remaining = policy.daily_exposure_limit_micros - budget.spent_micros - budget.reserved_micros
    if reserve > policy.max_job_exposure_micros or reserve > remaining:
        return result("BUDGET_LOCK", "job_or_daily_exposure_cap", cost, net, reserve)
    return result("READY_FOR_VERIFICATION_SHADOW", "forecast_only_independent_verification_required",
                  cost, net, reserve)


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proposal", required=True, type=Path,
                        help="untrusted offline JSON; never a genuine S1-MUPP state")
    args = parser.parse_args()
    try:
        with args.proposal.open("rb") as proposal_file:
            payload = proposal_file.read(MAX_INPUT_BYTES + 1)
        if len(payload) > MAX_INPUT_BYTES:
            raise ValueError("proposal exceeds 64 KiB")
        raw = json.loads(payload, object_pairs_hook=strict_object, parse_constant=reject_constant)
        required = {"quote", "policy", "budget", "observation"}
        if type(raw) is not dict or not required <= raw.keys() or raw.keys() - required - {"memory"}:
            raise ValueError("expected quote, policy, budget, observation and optional memory")
        if any(type(value) is not dict for value in raw.values()):
            raise ValueError("proposal sections must be JSON objects")
        now = time.time()
        memory = ControllerMemory.parse(raw.get("memory", {}))
        gate = evaluate(Observation.parse(raw["observation"]), memory, now)
        forecast = evaluate_quote(Quote.parse(raw["quote"]), Policy(**raw["policy"]),
                                  BudgetSnapshot(**raw["budget"]), gate, now)
        print(json.dumps({"forecast": asdict(forecast), "gate": asdict(gate)},
                         ensure_ascii=False, sort_keys=True))
    except (OSError, ValueError, TypeError, OverflowError) as exc:
        parser.error(f"invalid offline proposal: {exc}")


if __name__ == "__main__":
    main()
