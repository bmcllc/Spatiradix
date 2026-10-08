#!/usr/bin/env python3
"""Mycelium 4X v2 — local stress/survival Monte Carlo.

Extends mycelium_chain_sim_4x.py with:
- stochastic service demand;
- miner entry/churn;
- fee-fed LP plus community/solver LP withdrawals;
- adaptive PoVC emission capped at the original 1000 MYC/day ceiling;
- fraud attempts with risk-adaptive audits;
- BFT partitions with fail-closed finality;
- daily 4X controller=min(compute, work, demand, liquidity, security).

No Internet, external RPC, private keys or real-money execution.
All monetary quantities are hypothetical simulation units, not forecasts.
"""
from __future__ import annotations

import argparse
import json
import math
import random
import statistics
from dataclasses import dataclass, asdict
from pathlib import Path

import mycelium_chain_sim as base
import mycelium_chain_sim_4x as sim4x


EMISSION_CEILING_MYC_DAY = 1000.0
EMISSION_FLOOR_MYC_DAY = 150.0
BASE_EMISSION_MYC_DAY = 1000.0
BASE_SERVICE_REVENUE_MUSD_DAY = 500.0
BASE_MINERS = 10
BASE_WORK_UNITS_DAY = 1000.0
BASE_POOL_MYC = 100_000.0
BASE_POOL_MUSD = 10_000.0
AMM_FEE = 0.003

SERVICE_SPLIT = sim4x.SERVICE_SPLIT


@dataclass(frozen=True)
class StressProfile:
    name: str
    demand_sigma: float
    demand_crash_probability: float
    demand_crash_fraction: float
    lp_withdraw_probability: float
    lp_withdraw_fraction: float
    partition_probability: float
    partition_min_fraction_online: float
    fraud_attempt_probability_per_miner: float
    base_audit_probability: float
    new_miner_audit_probability: float
    suspicious_audit_probability: float
    description: str


PROFILES = {
    "normal": StressProfile(
        "normal", 0.12, 0.010, 0.45,
        0.005, 0.08,
        0.003, 0.45,
        0.0010, 0.05, 0.40, 0.90,
        "Moderate demand noise, rare small partitions and LP withdrawals.",
    ),
    "demand_shock": StressProfile(
        "demand_shock", 0.22, 0.040, 0.70,
        0.008, 0.10,
        0.004, 0.45,
        0.0010, 0.05, 0.40, 0.90,
        "Repeated demand contractions; network/security mostly healthy.",
    ),
    "liquidity_run": StressProfile(
        "liquidity_run", 0.15, 0.015, 0.50,
        0.045, 0.25,
        0.004, 0.45,
        0.0010, 0.05, 0.40, 0.90,
        "Community/solver LP is frequently withdrawn.",
    ),
    "partition": StressProfile(
        "partition", 0.14, 0.015, 0.50,
        0.008, 0.10,
        0.060, 0.20,
        0.0010, 0.05, 0.40, 0.90,
        "Frequent BFT network partitions; state finality fails closed.",
    ),
    "fraud": StressProfile(
        "fraud", 0.14, 0.015, 0.50,
        0.008, 0.10,
        0.004, 0.45,
        0.0200, 0.08, 0.60, 0.98,
        "High fraudulent-receipt pressure with adaptive auditing.",
    ),
    "combined": StressProfile(
        "combined", 0.25, 0.050, 0.70,
        0.040, 0.25,
        0.040, 0.20,
        0.0150, 0.08, 0.60, 0.98,
        "Demand, liquidity, partition and fraud stresses overlap.",
    ),
}


def clamp(x, lo, hi):
    return min(hi, max(lo, float(x)))


def adaptive_emission_myc(demand_ratio: float, fee_revenue_ratio: float,
                          finality_ok: bool) -> float:
    """Demand/fee-linked subsidy that may decrease but never exceeds 1000/day."""
    if not finality_ok:
        return 0.0
    signal = clamp(0.65 * demand_ratio + 0.35 * fee_revenue_ratio, 0.0, 1.0)
    return EMISSION_FLOOR_MYC_DAY + (
        EMISSION_CEILING_MYC_DAY - EMISSION_FLOOR_MYC_DAY
    ) * signal


def demand_step(rng: random.Random, previous_log_factor: float,
                profile: StressProfile):
    """Mean-reverting log-demand with occasional exogenous negative shock."""
    phi = 0.88
    eps = rng.gauss(0.0, profile.demand_sigma)
    log_factor = phi * previous_log_factor + eps
    shock = False
    if rng.random() < profile.demand_crash_probability:
        log_factor += math.log(max(0.05, 1.0 - profile.demand_crash_fraction))
        shock = True
    factor = clamp(math.exp(log_factor), 0.05, 4.0)
    return factor, log_factor, shock


def update_miners(rng: random.Random, miners: int, target_miners: int,
                  worker_income_per_miner: float,
                  baseline_income_per_miner: float):
    """Simple local labor supply response.

    Poor service income increases exits; high income attracts limited entrants.
    Churn is deliberately slow so the model cannot instantly equilibrate.
    """
    miners = max(1, int(miners))
    income_ratio = (
        worker_income_per_miner / max(baseline_income_per_miner, 1e-9)
    )
    exit_p = clamp(0.004 + 0.025 * max(0.0, 1.0 - income_ratio), 0.0, 0.08)
    entry_p = clamp(0.004 + 0.020 * max(0.0, income_ratio - 1.0), 0.0, 0.06)

    exits = sum(1 for _ in range(miners) if rng.random() < exit_p)
    room = max(0, int(target_miners * 2.0) - (miners - exits))
    candidate_entrants = max(1, target_miners // 5)
    entrants = min(
        room,
        sum(1 for _ in range(candidate_entrants) if rng.random() < entry_p),
    )
    return max(1, miners - exits + entrants), exits, entrants


def bft_partition_day(rng: random.Random, validators: int,
                      profile: StressProfile):
    """Return online validators and finality status under a random partition."""
    q = base.quorum(validators)
    partition = rng.random() < profile.partition_probability
    if not partition:
        return validators, True, False

    lo = max(0.05, profile.partition_min_fraction_online)
    online_fraction = rng.uniform(lo, 0.80)
    online = max(1, min(validators, int(math.floor(validators * online_fraction))))
    return online, online >= q, True


def adaptive_audit_probability(reputation: float, age_days: int,
                               suspicious: bool, profile: StressProfile):
    if suspicious:
        return profile.suspicious_audit_probability
    if age_days < 30:
        return profile.new_miner_audit_probability
    risk = 1.0 - clamp(reputation, 0.0, 1.0)
    return clamp(
        profile.base_audit_probability + 0.50 * risk,
        profile.base_audit_probability,
        profile.suspicious_audit_probability,
    )


def simulate_fraud_day(rng: random.Random, miners: int, reputations: list[float],
                       ages: list[int], profile: StressProfile):
    attempts = detected = escaped = 0
    slashed = 0
    for idx in range(miners):
        if rng.random() >= profile.fraud_attempt_probability_per_miner:
            continue
        attempts += 1
        suspicious = rng.random() < 0.35
        p_audit = adaptive_audit_probability(
            reputations[idx], ages[idx], suspicious, profile
        )
        if rng.random() < p_audit:
            detected += 1
            slashed += 1
            reputations[idx] = max(0.0, reputations[idx] - 0.25)
        else:
            escaped += 1
            reputations[idx] = max(0.0, reputations[idx] - 0.02)
    return attempts, detected, escaped, slashed


def resize_reputation_vectors(reputations, ages, miners):
    while len(reputations) < miners:
        reputations.append(0.90)
        ages.append(0)
    if len(reputations) > miners:
        del reputations[miners:]
        del ages[miners:]
    for i in range(len(ages)):
        ages[i] += 1


def remove_liquidity(x, y, fraction):
    fraction = clamp(fraction, 0.0, 0.80)
    return x * (1.0 - fraction), y * (1.0 - fraction)


def daily_controller(scale, execution_x, miners, demand_revenue,
                     x, y, finality_ok):
    work_x = miners / BASE_MINERS
    demand_x = demand_revenue / BASE_SERVICE_REVENUE_MUSD_DAY
    depth_x = math.sqrt(max(x, 0.0) * max(y, 0.0)) / math.sqrt(
        BASE_POOL_MYC * BASE_POOL_MUSD
    )
    security_x = float(scale) if finality_ok else 0.0
    factors = {
        "compute_execution_x": execution_x,
        "useful_work_x": min(4.0, work_x),
        "demand_x": min(4.0, demand_x),
        "liquidity_x": min(4.0, depth_x),
        "security_x": min(4.0, security_x),
    }
    controller = min(factors.values())
    bottleneck = min(factors, key=factors.get)
    return controller, bottleneck, factors


def one_trial(scale: int, profile: StressProfile, *, days=365,
              seed=1, miner_sell_fraction=0.50):
    rng = random.Random(seed)
    validators = sim4x.validator_count_for_scale(scale)
    q = base.quorum(validators)
    execution_x = sim4x.execution_speedup(scale)
    target_miners = BASE_MINERS * scale
    miners = target_miners
    reputations = [0.95] * miners
    ages = [90] * miners

    # Up to three externally supplied equal-price LP sources. Protocol LP begins
    # with zero capital and grows only from service fees.
    external_sources = min(scale, 3)
    x = BASE_POOL_MYC * external_sources
    y = BASE_POOL_MUSD * external_sources
    initial_depth = math.sqrt(BASE_POOL_MYC * BASE_POOL_MUSD)

    baseline_worker_income = (
        BASE_SERVICE_REVENUE_MUSD_DAY * SERVICE_SPLIT["worker"] / BASE_MINERS
    )
    log_demand = 0.0
    finality_paused_days = 0
    partition_days = 0
    demand_shock_days = 0
    lp_run_days = 0
    fraud_attempts = fraud_detected = fraud_escaped = slashed = 0
    myc_emitted = myc_sold = 0.0
    service_revenue_total = worker_income_total = 0.0
    validator_income_total = protocol_reserve_total = 0.0
    lp_fee_budget_total = 0.0
    min_controller = float("inf")
    controller_sum = 0.0
    active_controller_values = []
    bottleneck_counts = {}
    min_depth_x = float("inf")
    min_spot = float("inf")
    max_spot = 0.0
    peak_miners = miners
    min_miners = miners
    daily_snapshots = []

    for day in range(1, days + 1):
        demand_factor, log_demand, shocked = demand_step(
            rng, log_demand, profile
        )
        if shocked:
            demand_shock_days += 1
        service_revenue = BASE_SERVICE_REVENUE_MUSD_DAY * scale * demand_factor

        online_validators, finality_ok, partitioned = bft_partition_day(
            rng, validators, profile
        )
        if partitioned:
            partition_days += 1
        if not finality_ok:
            finality_paused_days += 1

        worker_fee = service_revenue * SERVICE_SPLIT["worker"]
        worker_income_per_miner = worker_fee / max(1, miners)

        miners, exits, entrants = update_miners(
            rng, miners, target_miners,
            worker_income_per_miner, baseline_worker_income,
        )
        resize_reputation_vectors(reputations, ages, miners)
        peak_miners = max(peak_miners, miners)
        min_miners = min(min_miners, miners)

        attempts, detected, escaped, day_slashed = simulate_fraud_day(
            rng, miners, reputations, ages, profile
        )
        fraud_attempts += attempts
        fraud_detected += detected
        fraud_escaped += escaped
        slashed += day_slashed

        # If finality is unavailable, jobs/receipts may remain pending but no
        # rewards, DEX state or protocol accounting are finalized that day.
        if finality_ok:
            validator_fee = service_revenue * SERVICE_SPLIT["validators"]
            lp_budget = service_revenue * SERVICE_SPLIT["lp"]
            protocol_fee = service_revenue * SERVICE_SPLIT["protocol_reserve"]

            # Random community/solver LP withdrawal before fee-fed replenishment.
            if rng.random() < profile.lp_withdraw_probability:
                withdraw_fraction = rng.uniform(
                    profile.lp_withdraw_fraction * 0.4,
                    profile.lp_withdraw_fraction,
                )
                x, y = remove_liquidity(x, y, withdraw_fraction)
                lp_run_days += 1

            x, y, _bought, paired_musd, _residual = sim4x.add_fee_fed_liquidity(
                x, y, lp_budget, fee=AMM_FEE
            )

            demand_ratio = clamp(demand_factor, 0.0, 1.0)
            fee_ratio = clamp(
                service_revenue /
                max(BASE_SERVICE_REVENUE_MUSD_DAY * scale, 1e-9),
                0.0, 1.0,
            )
            emission = adaptive_emission_myc(
                demand_ratio, fee_ratio, finality_ok=True
            )
            # Fraudulent escaped receipts dilute honest emission but cannot
            # increase the bounded epoch budget.
            dilution = (
                fraud_escaped / fraud_attempts
                if fraud_attempts > 0 else 0.0
            )
            honest_emission = emission * (1.0 - min(0.25, dilution * 0.25))
            sell_myc = honest_emission * miner_sell_fraction
            x, y, _miner_musd = base.cp_swap_x_for_y(
                x, y, sell_myc, AMM_FEE
            )

            myc_emitted += emission
            myc_sold += sell_myc
            service_revenue_total += service_revenue
            worker_income_total += worker_fee
            validator_income_total += validator_fee
            protocol_reserve_total += protocol_fee
            lp_fee_budget_total += lp_budget
        else:
            emission = 0.0
            paired_musd = 0.0

        controller, bottleneck, factors = daily_controller(
            scale, execution_x, miners, service_revenue, x, y, finality_ok
        )
        controller_sum += controller
        min_controller = min(min_controller, controller)
        if finality_ok:
            active_controller_values.append(controller)
        bottleneck_counts[bottleneck] = bottleneck_counts.get(bottleneck, 0) + 1

        depth_x = math.sqrt(x * y) / initial_depth
        spot = y / x
        min_depth_x = min(min_depth_x, depth_x)
        min_spot = min(min_spot, spot)
        max_spot = max(max_spot, spot)

        if day in (1, 7, 30, 90, 180, 365) or day == days:
            daily_snapshots.append({
                "day": day,
                "demand_factor": demand_factor,
                "service_revenue_musd": service_revenue,
                "miners": miners,
                "online_validators": online_validators,
                "quorum": q,
                "finality_ok": finality_ok,
                "emission_myc": emission,
                "spot_musd_per_myc": spot,
                "liquidity_depth_x": depth_x,
                "controller_x": controller,
                "bottleneck": bottleneck,
                "controller_factors": factors,
            })

    final_depth_x = math.sqrt(x * y) / initial_depth
    final_spot = y / x
    fraud_detection_rate = (
        fraud_detected / fraud_attempts if fraud_attempts else 1.0
    )
    finality_availability = 1.0 - finality_paused_days / days
    active_controller_median = (
        statistics.median(active_controller_values)
        if active_controller_values else 0.0
    )
    active_controller_p05 = (
        quantile(active_controller_values, 0.05)
        if active_controller_values else 0.0
    )

    # Fraud is a survival gate only when enough attempts exist to make the
    # empirical rate meaningful. Sparse low-risk profiles are reported but not
    # failed by one or two Bernoulli outcomes.
    fraud_gate_ok = (
        fraud_attempts < 20 or fraud_detection_rate >= 0.50
    )

    # A fail-closed partition day is not a state-safety failure by itself.
    # Survival measures whether the system remains solvent/available enough
    # over the whole period and resumes after partitions.
    survival = (
        finality_availability >= 0.95
        and final_depth_x >= 0.50
        and min_miners >= max(1, int(target_miners * 0.40))
        and fraud_gate_ok
        and math.isfinite(final_spot)
        and final_spot > 0.0
    )
    degraded = (
        not survival
        or finality_availability < 0.99
        or final_depth_x < float(scale) * 0.75
        or active_controller_median < min(float(scale) * 0.65, 2.5)
    )

    return {
        "scale": scale,
        "profile": profile.name,
        "seed": seed,
        "days": days,
        "survived": survival,
        "degraded": degraded,
        "execution_speedup_x": execution_x,
        "validators": validators,
        "quorum": q,
        "target_miners": target_miners,
        "final_miners": miners,
        "min_miners": min_miners,
        "peak_miners": peak_miners,
        "finality": {
            "partition_days": partition_days,
            "paused_days": finality_paused_days,
            "availability": finality_availability,
        },
        "demand": {
            "shock_days": demand_shock_days,
            "service_revenue_total_musd": service_revenue_total,
            "average_finalized_service_revenue_musd_per_day":
                service_revenue_total / days,
        },
        "liquidity": {
            "run_days": lp_run_days,
            "final_depth_x": final_depth_x,
            "minimum_depth_x": min_depth_x,
            "final_spot_musd_per_myc": final_spot,
            "minimum_spot_musd_per_myc": min_spot,
            "maximum_spot_musd_per_myc": max_spot,
            "final_dynamic_trade_max_myc_1pct":
                sim4x.dynamic_trade_max_myc(x, fee=AMM_FEE),
        },
        "povc": {
            "emitted_myc_total": myc_emitted,
            "average_emission_myc_per_day": myc_emitted / days,
            "sold_myc_total": myc_sold,
        },
        "fraud": {
            "attempts": fraud_attempts,
            "detected": fraud_detected,
            "escaped": fraud_escaped,
            "detection_rate": fraud_detection_rate,
            "slashed_events": slashed,
        },
        "income": {
            "worker_service_income_musd": worker_income_total,
            "validator_income_musd": validator_income_total,
            "protocol_reserve_musd": protocol_reserve_total,
            "lp_fee_budget_musd": lp_fee_budget_total,
        },
        "controller": {
            "average_x": controller_sum / days,
            "minimum_x_including_fail_closed_partitions": min_controller,
            "active_median_x": active_controller_median,
            "active_p05_x": active_controller_p05,
            "bottleneck_day_counts": bottleneck_counts,
        },
        "snapshots": daily_snapshots,
    }


def quantile(values, p):
    if not values:
        return None
    vals = sorted(float(x) for x in values)
    idx = min(len(vals) - 1, max(0, int(round((len(vals)-1) * p))))
    return vals[idx]


def aggregate_trials(trials):
    return {
        "trials": len(trials),
        "survival_rate": sum(t["survived"] for t in trials) / len(trials),
        "degraded_rate": sum(t["degraded"] for t in trials) / len(trials),
        "finality_availability": {
            "median": statistics.median(
                t["finality"]["availability"] for t in trials
            ),
            "p05": quantile(
                [t["finality"]["availability"] for t in trials], 0.05
            ),
        },
        "final_liquidity_depth_x": {
            "median": statistics.median(
                t["liquidity"]["final_depth_x"] for t in trials
            ),
            "p05": quantile(
                [t["liquidity"]["final_depth_x"] for t in trials], 0.05
            ),
        },
        "minimum_liquidity_depth_x": {
            "median": statistics.median(
                t["liquidity"]["minimum_depth_x"] for t in trials
            ),
            "p05": quantile(
                [t["liquidity"]["minimum_depth_x"] for t in trials], 0.05
            ),
        },
        "final_spot_musd_per_myc": {
            "median": statistics.median(
                t["liquidity"]["final_spot_musd_per_myc"] for t in trials
            ),
            "p05": quantile(
                [t["liquidity"]["final_spot_musd_per_myc"] for t in trials],
                0.05,
            ),
            "p95": quantile(
                [t["liquidity"]["final_spot_musd_per_myc"] for t in trials],
                0.95,
            ),
        },
        "average_emission_myc_per_day": {
            "median": statistics.median(
                t["povc"]["average_emission_myc_per_day"] for t in trials
            ),
            "p05": quantile(
                [t["povc"]["average_emission_myc_per_day"] for t in trials],
                0.05,
            ),
            "p95": quantile(
                [t["povc"]["average_emission_myc_per_day"] for t in trials],
                0.95,
            ),
        },
        "fraud_detection_rate": {
            "median": statistics.median(
                t["fraud"]["detection_rate"] for t in trials
            ),
            "p05": quantile(
                [t["fraud"]["detection_rate"] for t in trials], 0.05
            ),
        },
        "controller_average_x": {
            "median": statistics.median(
                t["controller"]["average_x"] for t in trials
            ),
            "p05": quantile(
                [t["controller"]["average_x"] for t in trials], 0.05
            ),
        },
        "controller_active_median_x": {
            "median": statistics.median(
                t["controller"]["active_median_x"] for t in trials
            ),
            "p05": quantile(
                [t["controller"]["active_median_x"] for t in trials], 0.05
            ),
        },
        "controller_active_p05_x": {
            "median": statistics.median(
                t["controller"]["active_p05_x"] for t in trials
            ),
            "p05": quantile(
                [t["controller"]["active_p05_x"] for t in trials], 0.05
            ),
        },
        "service_revenue_total_musd": {
            "median": statistics.median(
                t["demand"]["service_revenue_total_musd"] for t in trials
            ),
            "p05": quantile(
                [t["demand"]["service_revenue_total_musd"] for t in trials],
                0.05,
            ),
        },
    }


def run_monte_carlo(*, scale=4, days=365, trials=200,
                    miner_sell_fraction=0.50, seed=20260927):
    if scale not in (1, 2, 3, 4):
        raise ValueError("scale must be 1..4")
    if not 1 <= trials <= 5000:
        raise ValueError("trials must be 1..5000")
    results = {}
    for profile_name, profile in PROFILES.items():
        rows = [
            one_trial(
                scale, profile, days=days,
                seed=seed + i * 1009 + scale * 7919,
                miner_sell_fraction=miner_sell_fraction,
            )
            for i in range(trials)
        ]
        results[profile_name] = {
            "profile": asdict(profile),
            "aggregate": aggregate_trials(rows),
            "representative_trial": rows[0],
        }
    return {
        "kind": "MYCELIUM_CHAIN_4X_V2_STRESS_MONTE_CARLO",
        "version": 2,
        "real_money": False,
        "external_network_required": False,
        "price_forecast": False,
        "scale": scale,
        "days": days,
        "trials_per_profile": trials,
        "miner_sell_fraction": miner_sell_fraction,
        "emission": {
            "ceiling_myc_per_day": EMISSION_CEILING_MYC_DAY,
            "floor_myc_per_day_when_finality_available":
                EMISSION_FLOOR_MYC_DAY,
            "scales_with_4x": False,
            "zero_when_no_bft_finality": True,
        },
        "profiles": results,
        "survival_definition": {
            "finality_availability_min": 0.95,
            "final_liquidity_depth_x_min": 0.50,
            "minimum_miner_fraction_of_target": 0.40,
            "fraud_detection_rate_min_when_attempts_ge_20": 0.50,
            "positive_finite_amm_spot_required": True,
        },
        "invariants": {
            "no_unbacked_musd_mint": True,
            "bft_finality_fail_closed": True,
            "povc_cannot_exceed_emission_ceiling": True,
            "fraud_cannot_increase_epoch_emission_budget": True,
            "protocol_initial_lp_capital_required": 0.0,
        },
        "limitations": [
            "This is a stochastic toy model for architecture stress, not a market forecast.",
            "No insolvency, oracle manipulation, MEV, external arbitrage or bridge failure is modeled.",
            "Liquidity providers are aggregated into a single constant-product virtual pool.",
            "Miner entry/churn behavior is synthetic and must later be calibrated with real usage.",
            "Fraud verification is abstracted into audit probabilities, not cryptographic proof costs.",
        ],
    }


def main():
    ap = argparse.ArgumentParser(
        description="Mycelium 4X v2 local stress/survival simulation"
    )
    ap.add_argument("--scale", type=int, default=4)
    ap.add_argument("--days", type=int, default=365)
    ap.add_argument("--trials", type=int, default=200)
    ap.add_argument("--miner-sell-fraction", type=float, default=0.50)
    ap.add_argument("--seed", type=int, default=20260927)
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()
    if not 1 <= args.days <= 3650:
        raise SystemExit("days out of range")
    if not 0.0 <= args.miner_sell_fraction <= 1.0:
        raise SystemExit("miner sell fraction out of range")
    report = run_monte_carlo(
        scale=args.scale,
        days=args.days,
        trials=args.trials,
        miner_sell_fraction=args.miner_sell_fraction,
        seed=args.seed,
    )
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.out:
        if not args.out.is_absolute():
            raise SystemExit("--out must be absolute")
        args.out.write_text(payload)
    print(payload, end="")


if __name__ == "__main__":
    main()
