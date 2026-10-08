#!/usr/bin/env python3
"""Mycelium 4X local simulation.

Goal:
    Scale throughput, useful work, service revenue and liquidity toward 4X
    without scaling MYC subsidy 4X.

No Internet, external RPC, private keys or real-money execution is used.
All market values are hypothetical scenario inputs, not forecasts.
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

import mycelium_chain_sim as base


BASE_MYC_EMISSION_PER_DAY = 1000.0
BASE_SERVICE_REVENUE_MUSD_PER_DAY = 500.0
BASE_MINERS = 10
BASE_WORK_UNITS_PER_DAY = 1000.0
BASE_MYC_RESERVE = 100_000.0
BASE_MUSD_RESERVE = 10_000.0
BASE_OPS_PER_SECOND_ASSUMPTION = 1000.0

SERVICE_SPLIT = {
    "worker": 0.85,
    "validators": 0.05,
    "lp": 0.05,
    "protocol_reserve": 0.05,
}


def execution_speedup(lanes: int, *, parallel_fraction=0.92,
                      overhead_per_extra_lane=0.02) -> float:
    """Amdahl-style execution model plus deterministic coordination overhead."""
    if not 1 <= lanes <= 4:
        raise ValueError("lanes must be 1..4")
    serial = 1.0 - parallel_fraction
    amdahl = 1.0 / (serial + parallel_fraction / lanes)
    overhead = 1.0 + overhead_per_extra_lane * (lanes - 1)
    return amdahl / overhead


def validator_count_for_scale(scale: int) -> int:
    # 3f+1 committees: 4,7,10,13 => tolerate f=1,2,3,4.
    if not 1 <= scale <= 4:
        raise ValueError("scale must be 1..4")
    return 3 * scale + 1


def dynamic_trade_max_myc(myc_reserve: float, *, max_total_deviation=0.01,
                          fee=0.003, hard_reserve_fraction=0.01,
                          volatility_multiplier=1.0) -> float:
    """Max x->y trade respecting both reserve and AMM impact constraints.

    Average execution/spot for constant-product x->y:
        ratio = f*x/(x+f*dx)
    where f=(1-fee). Solve ratio >= 1-max_total_deviation.
    """
    if myc_reserve <= 0:
        return 0.0
    f = 1.0 - fee
    target = 1.0 - max_total_deviation
    if f <= target:
        impact_limit = 0.0
    else:
        impact_limit = (
            myc_reserve * (f - target) / (target * f)
        )
    reserve_limit = hard_reserve_fraction * myc_reserve
    return max(
        0.0,
        min(impact_limit, reserve_limit) / max(volatility_multiplier, 1.0),
    )


def add_fee_fed_liquidity(x: float, y: float, lp_budget_musd: float,
                          *, fee=0.003):
    """Grow LP from service fees without protocol initial capital.

    Half the LP budget buys MYC from the AMM. The other half is paired with
    enough of the acquired MYC at the post-buy spot. Residual MYC remains a
    staging balance for future LP operations.
    """
    if lp_budget_musd <= 0:
        return x, y, 0.0, 0.0, 0.0

    buy_budget = lp_budget_musd * 0.5
    pair_budget = lp_budget_musd - buy_budget

    x, y, bought_myc = base.cp_swap_y_for_x(x, y, buy_budget, fee)
    spot = y / x
    needed_myc = pair_budget / spot
    paired_myc = min(bought_myc, needed_myc)
    paired_musd = paired_myc * spot

    x += paired_myc
    y += paired_musd
    residual_myc = max(0.0, bought_myc - paired_myc)
    return x, y, bought_myc, paired_musd, residual_myc


def economic_lane_sim(scale: int, *, days=365, fee=0.003,
                      miner_sell_fraction=0.50):
    """Simulate one 1X..4X scenario with fixed MYC emission."""
    if not 1 <= scale <= 4:
        raise ValueError("scale must be 1..4")

    miners = BASE_MINERS * scale
    service_revenue = BASE_SERVICE_REVENUE_MUSD_PER_DAY * scale
    work_capacity = BASE_WORK_UNITS_PER_DAY * scale

    # Liquidity sources: local, community and solver are externally supplied.
    # The fourth source is fee-fed protocol liquidity that starts at zero.
    external_sources = min(scale, 3)
    x = BASE_MYC_RESERVE * external_sources
    y = BASE_MUSD_RESERVE * external_sources

    initial_depth = math.sqrt(BASE_MYC_RESERVE * BASE_MUSD_RESERVE)
    history = []
    lp_residual_myc = 0.0
    cumulative = {
        "service_revenue_musd": 0.0,
        "worker_service_income_musd": 0.0,
        "validator_income_musd": 0.0,
        "protocol_reserve_musd": 0.0,
        "lp_budget_musd": 0.0,
        "miner_myc_sold": 0.0,
        "miner_musd_from_sales": 0.0,
        "lp_musd_added": 0.0,
    }

    for day in range(1, days + 1):
        worker_fee = service_revenue * SERVICE_SPLIT["worker"]
        validator_fee = service_revenue * SERVICE_SPLIT["validators"]
        lp_budget = service_revenue * SERVICE_SPLIT["lp"]
        protocol_fee = service_revenue * SERVICE_SPLIT["protocol_reserve"]

        # Fee-fed LP: no initial protocol capital is injected.
        x, y, bought_myc, paired_musd, residual_myc = add_fee_fed_liquidity(
            x, y, lp_budget, fee=fee
        )
        lp_residual_myc += residual_myc

        # PoVC subsidy stays fixed at 1000 MYC/day at every scale.
        miner_sell_myc = BASE_MYC_EMISSION_PER_DAY * miner_sell_fraction
        x, y, miner_musd = base.cp_swap_x_for_y(
            x, y, miner_sell_myc, fee
        )

        cumulative["service_revenue_musd"] += service_revenue
        cumulative["worker_service_income_musd"] += worker_fee
        cumulative["validator_income_musd"] += validator_fee
        cumulative["protocol_reserve_musd"] += protocol_fee
        cumulative["lp_budget_musd"] += lp_budget
        cumulative["miner_myc_sold"] += miner_sell_myc
        cumulative["miner_musd_from_sales"] += miner_musd
        cumulative["lp_musd_added"] += paired_musd

        if day in (1, 7, 30, 90, 180, 365) or day == days:
            history.append({
                "day": day,
                "spot_musd_per_myc": y / x,
                "myc_reserve": x,
                "musd_reserve": y,
                "liquidity_depth_x":
                    math.sqrt(x * y) / initial_depth,
                "dynamic_trade_max_myc_at_1pct_total_deviation":
                    dynamic_trade_max_myc(x, fee=fee),
            })

    final_price = y / x
    final_depth_x = math.sqrt(x * y) / initial_depth

    return {
        "scale_target_x": scale,
        "days": days,
        "miners": miners,
        "external_lp_sources": external_sources,
        "service_revenue_musd_per_day": service_revenue,
        "useful_work_capacity_units_per_day": work_capacity,
        "bounded_povc_emission_myc_per_day": BASE_MYC_EMISSION_PER_DAY,
        "myc_subsidy_per_miner_per_day": BASE_MYC_EMISSION_PER_DAY / miners,
        "worker_service_income_musd_per_miner_per_day":
            (service_revenue * SERVICE_SPLIT["worker"]) / miners,
        "miner_sell_fraction": miner_sell_fraction,
        "initial_pool": {
            "myc": BASE_MYC_RESERVE * external_sources,
            "musd": BASE_MUSD_RESERVE * external_sources,
            "spot": 0.10,
        },
        "final_pool": {
            "myc": x,
            "musd": y,
            "spot_musd_per_myc": final_price,
            "liquidity_depth_x": final_depth_x,
            "dynamic_trade_max_myc_at_1pct_total_deviation":
                dynamic_trade_max_myc(x, fee=fee),
        },
        "lp_staging_residual_myc": lp_residual_myc,
        "cumulative": cumulative,
        "history": history,
    }


def throughput_model(scale: int):
    lanes = scale
    speedup = execution_speedup(lanes)
    validators = validator_count_for_scale(scale)
    consensus = base.latency_sim(
        validators,
        trials=3000,
        median_ms=2.0,
        p95_ms=8.0,
        verify_ms=0.5,
        aggregate_ms=1.0,
        seed=4400,
    )
    return {
        "active_execution_lanes": lanes,
        "theoretical_ideal_speedup_x": float(lanes),
        "modeled_execution_speedup_x": speedup,
        "hypothetical_ops_per_second_at_1000_base":
            BASE_OPS_PER_SECOND_ASSUMPTION * speedup,
        "parallel_fraction_assumption": 0.92,
        "coordination_overhead_per_extra_lane": 0.02,
        "validators": validators,
        "quorum": base.quorum(validators),
        "byzantine_tolerance": base.byzantine_tolerance(validators),
        "qc_latency_ms": consensus["qc_latency_ms"],
    }


def bottleneck_report(scale: int, throughput: dict, econ: dict):
    x_compute = throughput["modeled_execution_speedup_x"]
    x_demand = econ["service_revenue_musd_per_day"] / BASE_SERVICE_REVENUE_MUSD_PER_DAY
    x_liquidity = min(4.0, econ["final_pool"]["liquidity_depth_x"])
    # Relative resilience tier: f=1 => 1X ... f=4 => 4X.
    x_security = min(4.0, float(throughput["byzantine_tolerance"]))
    x_work = econ["useful_work_capacity_units_per_day"] / BASE_WORK_UNITS_PER_DAY

    factors = {
        "compute_execution_x": x_compute,
        "useful_work_x": x_work,
        "demand_x": x_demand,
        "liquidity_x": x_liquidity,
        "security_resilience_x": x_security,
    }
    controller = min(factors.values())
    eps = 1e-9
    bottlenecks = [
        name for name, value in factors.items()
        if abs(value - controller) <= eps
    ]
    return {
        "factors": factors,
        "controller_x": controller,
        "bottleneck": bottlenecks,
        "target_x": float(scale),
        "target_reached": controller >= scale - 1e-9,
    }


def build_report(days=365, miner_sell_fraction=0.50):
    scenarios = []
    for scale in range(1, 5):
        throughput = throughput_model(scale)
        econ = economic_lane_sim(
            scale, days=days, miner_sell_fraction=miner_sell_fraction
        )
        bottleneck = bottleneck_report(scale, throughput, econ)
        scenarios.append({
            "scale": scale,
            "throughput": throughput,
            "economics": econ,
            "controller": bottleneck,
        })

    return {
        "kind": "MYCELIUM_CHAIN_4X_LOCAL_SIMULATION",
        "version": 1,
        "real_money": False,
        "external_network_required": False,
        "price_forecast": False,
        "days": days,
        "fixed_parameters": {
            "myc_emission_myc_per_day_all_scales":
                BASE_MYC_EMISSION_PER_DAY,
            "base_service_revenue_musd_per_day":
                BASE_SERVICE_REVENUE_MUSD_PER_DAY,
            "base_miners": BASE_MINERS,
            "base_work_units_per_day": BASE_WORK_UNITS_PER_DAY,
            "service_split": SERVICE_SPLIT,
            "miner_sell_fraction": miner_sell_fraction,
            "amm_fee": 0.003,
            "base_pool": {
                "myc": BASE_MYC_RESERVE,
                "musd": BASE_MUSD_RESERVE,
                "spot": 0.10,
            },
            "ops_per_second_assumption_only":
                BASE_OPS_PER_SECOND_ASSUMPTION,
        },
        "scenarios": scenarios,
        "invariants": {
            "emission_scales_with_x": False,
            "consensus_is_separate_from_povc": True,
            "musd_is_mined": False,
            "service_income_can_scale_without_myc_inflation": True,
            "protocol_initial_external_lp_capital_required": 0.0,
            "external_or_community_liquidity_required": True,
        },
        "limitations": [
            "AMM model aggregates same-price liquidity sources into one virtual pool.",
            "No external arbitrageurs, speculation, oracle shocks or insolvency are modeled.",
            "The 1000 ops/s base is a configurable normalization, not a benchmark.",
            "Service revenue and work demand are scenario inputs, not forecasts.",
            "Security_resilience_x is a relative BFT fault-tolerance tier, not throughput.",
        ],
    }


def main():
    ap = argparse.ArgumentParser(description="Local Mycelium Chain 4X simulator")
    ap.add_argument("--days", type=int, default=365)
    ap.add_argument("--miner-sell-fraction", type=float, default=0.50)
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()
    if not 1 <= args.days <= 3650:
        raise SystemExit("days out of range")
    if not 0.0 <= args.miner_sell_fraction <= 1.0:
        raise SystemExit("miner sell fraction out of range")
    report = build_report(args.days, args.miner_sell_fraction)
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.out:
        if not args.out.is_absolute():
            raise SystemExit("--out must be absolute")
        args.out.write_text(payload)
    print(payload, end="")


if __name__ == "__main__":
    main()
