#!/usr/bin/env python3
"""Mycelium 4X v3 — Adaptive Defense Kernel + local policy search.

Central idea:
    R_t = (r_worker, r_liquidity, r_fraud, r_partition)
    Pi_t = {emission, worker_floor, WSR contribution, LP share,
            audit floor, trade max}

Hard invariants:
    MYC emission <= 1000/day
    no quorum => no finality => emission = 0
    no unbacked mUSD mint (the simulator never mints mUSD)
    stress defenses are funded by prior/current service revenue, not
    mandatory protocol seed capital

All simulation is local and deterministic for a given seed.
No Internet, external RPC, private keys or real-money execution.
"""
from __future__ import annotations

import argparse
import json
import math
import random
import statistics
import subprocess
import time
from dataclasses import dataclass, asdict
from pathlib import Path

import mycelium_chain_sim as base
import mycelium_chain_sim_4x as sim4x
import mycelium_chain_sim_4x_v2 as v2


BASE_WORKER_INCOME_MUSD_DAY = 42.5
BASE_SERVICE_REVENUE_MUSD_DAY = 500.0
BASE_MINERS = 10
BASE_POOL_MYC = 100_000.0
BASE_POOL_MUSD = 10_000.0
EMISSION_CEILING_MYC_DAY = 1000.0
EMISSION_FLOOR_MYC_DAY = 100.0
AMM_FEE = 0.003


@dataclass(frozen=True)
class DefensePolicy:
    worker_floor_ratio: float = 0.60
    reserve_target_days: int = 14
    bootstrap_wsr_share: float = 0.10
    maintenance_wsr_share: float = 0.05
    validator_share: float = 0.05
    general_reserve_share: float = 0.05
    lp_share_normal: float = 0.05
    lp_share_max: float = 0.15
    liquidity_target_x: float = 2.0
    liquidity_emergency_x: float = 0.60
    audit_base: float = 0.15
    audit_risk_alpha: float = 0.45
    audit_value_beta: float = 0.20
    audit_novelty_gamma: float = 0.15
    audit_anomaly_delta: float = 0.35
    risk_memory_lambda: float = 0.80
    churn_sensitivity: float = 0.65
    trade_impact_limit: float = 0.01
    trade_volatility_lambda: float = 4.0
    receipt_ttl_days: int = 14
    recovery_backlog_multiple: float = 1.5
    emission_liquidity_brake: float = 0.55
    emission_partition_brake: float = 0.25


@dataclass
class KernelState:
    worker_stability_reserve_musd: float = 0.0
    general_reserve_musd: float = 0.0
    fraud_risk_memory: float = 0.0
    partition_risk_memory: float = 0.0
    volatility_ewma: float = 0.0
    previous_spot: float = 0.10
    deferred_sell_myc: float = 0.0


@dataclass(frozen=True)
class RiskVector:
    r_worker: float
    r_liquidity: float
    r_fraud: float
    r_partition: float




def cpu_temp_c():
    """Best-effort local thermal read; None means unavailable."""
    try:
        raw=subprocess.check_output(
            ["sensors","-j"], text=True, stderr=subprocess.DEVNULL, timeout=2
        )
        data=json.loads(raw)
        pkg=data.get("coretemp-isa-0000",{}).get("Package id 0",{})
        for key,value in pkg.items():
            if key.endswith("_input"):
                return float(value)
    except Exception:
        return None
    return None


def thermal_gate(max_temp_c=78.0, resume_temp_c=72.0, max_wait_s=120):
    """Fail-safe local gate used only by policy search."""
    start=time.monotonic()
    while True:
        temp=cpu_temp_c()
        if temp is None:
            return {"available":False,"temp_c":None,"waited_s":0.0}
        if temp <= max_temp_c:
            return {"available":True,"temp_c":temp,
                    "waited_s":time.monotonic()-start}
        if time.monotonic()-start >= max_wait_s:
            raise RuntimeError(f"THERMAL_GATE_TIMEOUT:{temp:.1f}C")
        time.sleep(2.0)
        # Once cooling starts, require a lower restart point to avoid oscillation.
        max_temp_c=resume_temp_c

def clamp(x, lo=0.0, hi=1.0):
    return min(hi, max(lo, float(x)))


def piecewise_liquidity_risk(depth_x: float, emergency_x=0.60,
                             target_x=2.0) -> float:
    if depth_x <= emergency_x:
        return 1.0
    if depth_x >= target_x:
        return 0.0
    return clamp((target_x - depth_x) / (target_x - emergency_x))


def worker_risk(service_income_per_miner: float, worker_floor: float,
                reserve: float, reserve_target: float) -> float:
    if worker_floor <= 0:
        return 0.0
    income_gap = clamp(
        (worker_floor - service_income_per_miner) / worker_floor
    )
    reserve_gap = clamp(
        (reserve_target - reserve) / max(reserve_target, 1e-9)
    )
    return clamp(0.75 * income_gap + 0.25 * reserve_gap)


def partition_risk_update(previous: float, finality_ok: bool,
                          online: int, quorum: int, lam=0.85) -> float:
    margin = (online - quorum) / max(quorum, 1)
    instant = 1.0 if not finality_ok else clamp(0.25 - margin, 0.0, 1.0)
    return clamp(lam * previous + (1.0 - lam) * instant)


def adaptive_audit_probability(policy: DefensePolicy, miner_risk: float,
                               value_risk: float, novelty: float,
                               anomaly: float) -> float:
    p = (
        policy.audit_base
        + policy.audit_risk_alpha * clamp(miner_risk)
        + policy.audit_value_beta * clamp(value_risk)
        + policy.audit_novelty_gamma * clamp(novelty)
        + policy.audit_anomaly_delta * clamp(anomaly)
    )
    return clamp(p, policy.audit_base, 1.0)


def compute_risks(policy: DefensePolicy, state: KernelState, *,
                  service_income_per_miner: float,
                  worker_floor: float,
                  reserve_target: float,
                  liquidity_depth_x: float,
                  finality_ok: bool,
                  online_validators: int,
                  quorum: int) -> RiskVector:
    rw = worker_risk(
        service_income_per_miner, worker_floor,
        state.worker_stability_reserve_musd, reserve_target
    )
    rl = piecewise_liquidity_risk(
        liquidity_depth_x,
        emergency_x=policy.liquidity_emergency_x,
        target_x=policy.liquidity_target_x,
    )
    rp = partition_risk_update(
        state.partition_risk_memory, finality_ok,
        online_validators, quorum
    )
    rf = clamp(state.fraud_risk_memory)
    return RiskVector(rw, rl, rf, rp)


def kernel_policy(policy: DefensePolicy, state: KernelState, risks: RiskVector,
                  *, service_revenue_musd: float, miners: int,
                  liquidity_depth_x: float, finality_ok: bool,
                  demand_ratio: float):
    """One coordinated policy; shares are computed together, not independently."""
    worker_floor = BASE_WORKER_INCOME_MUSD_DAY * policy.worker_floor_ratio
    reserve_target = worker_floor * miners * policy.reserve_target_days
    reserve_gap = clamp(
        (reserve_target - state.worker_stability_reserve_musd)
        / max(reserve_target, 1e-9)
    )

    # LP defense grows with liquidity risk, but worker distress gets first claim
    # when it materially exceeds liquidity risk.
    lp_share = policy.lp_share_normal + (
        policy.lp_share_max - policy.lp_share_normal
    ) * risks.r_liquidity
    if risks.r_worker > risks.r_liquidity + 0.15:
        lp_share *= (1.0 - 0.55 * risks.r_worker)
    lp_share = clamp(lp_share, 0.01, policy.lp_share_max)

    # Save aggressively in good periods; stop filling the WSR while it is being
    # used to keep workers above the survival floor.
    base_wsr = (
        policy.bootstrap_wsr_share
        if reserve_gap > 0.05 else policy.maintenance_wsr_share
    )
    wsr_share = base_wsr * reserve_gap * (1.0 - risks.r_worker)
    if risks.r_worker > 0.55:
        wsr_share *= 0.20
    wsr_share = clamp(wsr_share, 0.0, policy.bootstrap_wsr_share)

    fixed = policy.validator_share + policy.general_reserve_share
    max_variable = max(0.0, 0.95 - fixed)
    if lp_share + wsr_share > max_variable:
        factor = max_variable / max(lp_share + wsr_share, 1e-12)
        lp_share *= factor
        wsr_share *= factor
    worker_share = max(0.0, 1.0 - fixed - lp_share - wsr_share)

    # Adaptive emission can only decrease from the hard ceiling.
    emission_signal = clamp(demand_ratio, 0.0, 1.0)
    emission = EMISSION_FLOOR_MYC_DAY + (
        EMISSION_CEILING_MYC_DAY - EMISSION_FLOOR_MYC_DAY
    ) * emission_signal
    emission *= (1.0 - policy.emission_liquidity_brake * risks.r_liquidity)
    emission *= (1.0 - policy.emission_partition_brake * risks.r_partition)
    emission = clamp(emission, 0.0, EMISSION_CEILING_MYC_DAY)
    if not finality_ok:
        emission = 0.0

    # TradeMax protects execution capacity, not price. Emergency liquidity
    # completely pauses protocol-managed automatic sells.
    if (not finality_ok) or liquidity_depth_x < policy.liquidity_emergency_x:
        trade_scale = 0.0
    else:
        liq_scale = min(
            1.0,
            liquidity_depth_x / max(policy.liquidity_target_x, 1e-9),
        )
        vol_scale = 1.0 / (
            1.0 + policy.trade_volatility_lambda * state.volatility_ewma
        )
        part_scale = 1.0 - 0.50 * risks.r_partition
        trade_scale = clamp(liq_scale * vol_scale * part_scale)

    return {
        "worker_floor_musd_per_miner": worker_floor,
        "reserve_target_musd": reserve_target,
        "worker_share": worker_share,
        "validator_share": policy.validator_share,
        "general_reserve_share": policy.general_reserve_share,
        "lp_share": lp_share,
        "wsr_contribution_share": wsr_share,
        "emission_myc": emission,
        "trade_scale": trade_scale,
        "audit_floor": policy.audit_base,
    }


def update_miners_v3(rng: random.Random, miners: int, target_miners: int,
                     effective_income_per_miner: float,
                     policy: DefensePolicy):
    income_ratio = (
        effective_income_per_miner / max(BASE_WORKER_INCOME_MUSD_DAY, 1e-9)
    )
    s = policy.churn_sensitivity
    exit_p = clamp(
        0.002 + s * 0.030 * max(0.0, 1.0 - income_ratio),
        0.0, 0.10,
    )
    entry_p = clamp(
        0.003 + 0.018 * max(0.0, income_ratio - 1.0),
        0.0, 0.05,
    )
    exits = sum(1 for _ in range(miners) if rng.random() < exit_p)
    room = max(0, int(target_miners * 2.0) - (miners - exits))
    candidates = max(1, target_miners // 4)
    entrants = min(
        room,
        sum(1 for _ in range(candidates) if rng.random() < entry_p),
    )
    return max(1, miners - exits + entrants), exits, entrants


def rebase_lp_tokens(x, y, external_l, protocol_l):
    actual_l = math.sqrt(max(x, 0.0) * max(y, 0.0))
    total = external_l + protocol_l
    if total <= 0:
        return actual_l, 0.0
    factor = actual_l / total
    return external_l * factor, protocol_l * factor


def external_lp_withdraw(x, y, external_l, protocol_l, fraction):
    external_l, protocol_l = rebase_lp_tokens(
        x, y, external_l, protocol_l
    )
    remove_l = external_l * clamp(fraction, 0.0, 0.90)
    total_l = external_l + protocol_l
    if total_l <= 0 or remove_l <= 0:
        return x, y, external_l, protocol_l, 0.0
    reserve_fraction = clamp(remove_l / total_l, 0.0, 0.90)
    x *= (1.0 - reserve_fraction)
    y *= (1.0 - reserve_fraction)
    external_l -= remove_l
    return x, y, external_l, protocol_l, reserve_fraction


def add_fee_fed_lp_owned(x, y, external_l, protocol_l, budget_musd):
    if budget_musd <= 0:
        return x, y, external_l, protocol_l, 0.0

    # Half buys MYC; existing LPs receive swap fees.
    buy_budget = budget_musd * 0.5
    pair_budget = budget_musd - buy_budget
    x, y, bought_myc = base.cp_swap_y_for_x(x, y, buy_budget, AMM_FEE)
    external_l, protocol_l = rebase_lp_tokens(
        x, y, external_l, protocol_l
    )

    before_l = math.sqrt(x * y)
    spot = y / x
    paired_myc = min(bought_myc, pair_budget / max(spot, 1e-12))
    paired_musd = paired_myc * spot
    x += paired_myc
    y += paired_musd
    after_l = math.sqrt(x * y)
    protocol_l += max(0.0, after_l - before_l)
    return x, y, external_l, protocol_l, paired_musd


def update_market_volatility(state: KernelState, spot: float, lam=0.90):
    if state.previous_spot > 0 and spot > 0:
        move = abs(math.log(spot / state.previous_spot))
    else:
        move = 0.0
    state.volatility_ewma = (
        lam * state.volatility_ewma + (1.0 - lam) * move
    )
    state.previous_spot = spot


def fraud_day_v3(rng: random.Random, miners: int, reputations: list[float],
                 ages: list[int], miner_risks: list[float],
                 profile: v2.StressProfile, policy: DefensePolicy):
    attempts = detected = escaped = slashed = audits = 0
    anomalies = 0.0
    for i in range(miners):
        # Background anomaly exists even without actual fraud.
        background_anomaly = 1.0 if rng.random() < 0.002 else 0.0
        miner_risks[i] = clamp(
            policy.risk_memory_lambda * miner_risks[i]
            + (1.0 - policy.risk_memory_lambda) * background_anomaly
        )

        if rng.random() >= profile.fraud_attempt_probability_per_miner:
            continue
        attempts += 1
        value_risk = clamp(rng.betavariate(2.0, 2.0))
        anomaly = 1.0 if rng.random() < 0.70 else 0.30
        novelty = 1.0 if ages[i] < 30 else 0.0
        anomalies += anomaly

        miner_risks[i] = clamp(
            policy.risk_memory_lambda * miner_risks[i]
            + (1.0 - policy.risk_memory_lambda) * anomaly
        )
        p = adaptive_audit_probability(
            policy, miner_risks[i], value_risk, novelty, anomaly
        )
        if rng.random() < p:
            audits += 1
            detected += 1
            slashed += 1
            miner_risks[i] = clamp(miner_risks[i] + 0.45)
            reputations[i] = max(0.0, reputations[i] - 0.30)
        else:
            escaped += 1
            reputations[i] = max(0.0, reputations[i] - 0.03)
    return {
        "attempts": attempts,
        "detected": detected,
        "escaped": escaped,
        "slashed": slashed,
        "audits": audits,
        "mean_anomaly_on_attempts": anomalies / attempts if attempts else 0.0,
    }


def resize_vectors(reputations, ages, miner_risks, miners):
    while len(reputations) < miners:
        reputations.append(0.90)
        ages.append(0)
        miner_risks.append(0.20)
    if len(reputations) > miners:
        del reputations[miners:]
        del ages[miners:]
        del miner_risks[miners:]
    for i in range(miners):
        ages[i] += 1


def queue_pending(pending, amount):
    if amount > 0:
        pending.append([0, float(amount)])


def age_and_expire_pending(pending, ttl_days):
    kept = []
    expired = 0.0
    for age, amount in pending:
        age += 1
        if age > ttl_days:
            expired += amount
        else:
            kept.append([age, amount])
    pending[:] = kept
    return expired


def release_pending(pending, capacity):
    released = 0.0
    kept = []
    for age, amount in pending:
        if capacity <= 0:
            kept.append([age, amount])
            continue
        take = min(amount, capacity)
        released += take
        capacity -= take
        remain = amount - take
        if remain > 1e-9:
            kept.append([age, remain])
    pending[:] = kept
    return released


def simulate_trial(scale: int, profile: v2.StressProfile,
                   policy: DefensePolicy, *, days=365,
                   seed=1, miner_sell_fraction=0.50):
    rng = random.Random(seed)
    validators = sim4x.validator_count_for_scale(scale)
    quorum = base.quorum(validators)
    target_miners = BASE_MINERS * scale
    miners = target_miners
    execution_x = sim4x.execution_speedup(scale)

    reputations = [0.95] * miners
    ages = [90] * miners
    miner_risks = [0.10] * miners
    state = KernelState()

    external_sources = min(scale, 3)
    x = BASE_POOL_MYC * external_sources
    y = BASE_POOL_MUSD * external_sources
    initial_l = math.sqrt(x * y)
    external_l = initial_l
    protocol_l = 0.0

    log_demand = 0.0
    pending_receipts = []
    finalized_income_trailing = []

    counters = {
        "partition_days": 0,
        "paused_days": 0,
        "demand_shock_days": 0,
        "lp_run_days": 0,
        "fraud_attempts": 0,
        "fraud_detected": 0,
        "fraud_escaped": 0,
        "audits": 0,
        "slashed": 0,
        "pending_expired_musd": 0.0,
        "treasury_sell_paused_days": 0,
        "worker_floor_supported_days": 0,
        "wsr_empty_days": 0,
    }
    totals = {
        "service_revenue_musd": 0.0,
        "worker_income_musd": 0.0,
        "validator_income_musd": 0.0,
        "lp_budget_musd": 0.0,
        "general_reserve_contrib_musd": 0.0,
        "wsr_contrib_musd": 0.0,
        "wsr_payout_musd": 0.0,
        "emission_myc": 0.0,
        "sold_myc": 0.0,
    }

    min_miners = miners
    max_miners = miners
    min_depth = float("inf")
    finality_ok_days = 0
    controller_active = []
    bottleneck_counts = {}
    risk_sums = [0.0, 0.0, 0.0, 0.0]
    snapshots = []

    for day in range(1, days + 1):
        demand_factor, log_demand, shocked = v2.demand_step(
            rng, log_demand, profile
        )
        if shocked:
            counters["demand_shock_days"] += 1
        raw_service_revenue = (
            BASE_SERVICE_REVENUE_MUSD_DAY * scale * demand_factor
        )

        online, finality_ok, partitioned = v2.bft_partition_day(
            rng, validators, profile
        )
        if partitioned:
            counters["partition_days"] += 1
        if not finality_ok:
            counters["paused_days"] += 1
        else:
            finality_ok_days += 1

        counters["pending_expired_musd"] += age_and_expire_pending(
            pending_receipts, policy.receipt_ttl_days
        )

        if not finality_ok:
            queue_pending(pending_receipts, raw_service_revenue)
            finalized_revenue = 0.0
        else:
            backlog_capacity = (
                raw_service_revenue * policy.recovery_backlog_multiple
            )
            backlog = release_pending(
                pending_receipts, backlog_capacity
            )
            finalized_revenue = raw_service_revenue + backlog

        depth_x = math.sqrt(x * y) / math.sqrt(
            BASE_POOL_MYC * BASE_POOL_MUSD
        )
        pre_worker_share = 0.80
        service_income_est = (
            finalized_revenue * pre_worker_share / max(miners, 1)
        )
        worker_floor = BASE_WORKER_INCOME_MUSD_DAY * policy.worker_floor_ratio
        reserve_target = (
            worker_floor * miners * policy.reserve_target_days
        )

        # Fraud risk memory is updated from the prior day and current evidence.
        state.partition_risk_memory = partition_risk_update(
            state.partition_risk_memory,
            finality_ok, online, quorum,
        )
        risks = compute_risks(
            policy, state,
            service_income_per_miner=service_income_est,
            worker_floor=worker_floor,
            reserve_target=reserve_target,
            liquidity_depth_x=depth_x,
            finality_ok=finality_ok,
            online_validators=online,
            quorum=quorum,
        )
        policy_out = kernel_policy(
            policy, state, risks,
            service_revenue_musd=finalized_revenue,
            miners=miners,
            liquidity_depth_x=depth_x,
            finality_ok=finality_ok,
            demand_ratio=demand_factor,
        )

        if finality_ok:
            worker_service = (
                finalized_revenue * policy_out["worker_share"]
            )
            validator_income = (
                finalized_revenue * policy_out["validator_share"]
            )
            lp_budget = finalized_revenue * policy_out["lp_share"]
            general_contrib = (
                finalized_revenue * policy_out["general_reserve_share"]
            )
            wsr_contrib = (
                finalized_revenue * policy_out["wsr_contribution_share"]
            )

            state.worker_stability_reserve_musd += wsr_contrib
            state.general_reserve_musd += general_contrib

            target_worker_total = worker_floor * miners
            floor_gap = max(0.0, target_worker_total - worker_service)
            wsr_payout = min(
                floor_gap, state.worker_stability_reserve_musd
            )
            state.worker_stability_reserve_musd -= wsr_payout
            effective_worker_income = worker_service + wsr_payout
            if wsr_payout > 0:
                counters["worker_floor_supported_days"] += 1
            if floor_gap > wsr_payout + 1e-9:
                counters["wsr_empty_days"] += 1

            # Only external/community liquidity is withdrawable. Fee-fed
            # protocol LP remains owned by the protocol.
            if rng.random() < profile.lp_withdraw_probability:
                frac = rng.uniform(
                    profile.lp_withdraw_fraction * 0.4,
                    profile.lp_withdraw_fraction,
                )
                x, y, external_l, protocol_l, _ = external_lp_withdraw(
                    x, y, external_l, protocol_l, frac
                )
                counters["lp_run_days"] += 1

            x, y, external_l, protocol_l, _ = add_fee_fed_lp_owned(
                x, y, external_l, protocol_l, lp_budget
            )

            fraud = fraud_day_v3(
                rng, miners, reputations, ages, miner_risks,
                profile, policy,
            )
            counters["fraud_attempts"] += fraud["attempts"]
            counters["fraud_detected"] += fraud["detected"]
            counters["fraud_escaped"] += fraud["escaped"]
            counters["audits"] += fraud["audits"]
            counters["slashed"] += fraud["slashed"]

            instant_fraud = (
                fraud["attempts"] / max(miners, 1)
            )
            state.fraud_risk_memory = clamp(
                policy.risk_memory_lambda * state.fraud_risk_memory
                + (1.0 - policy.risk_memory_lambda)
                * clamp(instant_fraud * 8.0)
            )

            emission = policy_out["emission_myc"]
            # Escaped fraud can capture part of the fixed budget, never create
            # additional emission.
            escape_ratio = (
                fraud["escaped"] / fraud["attempts"]
                if fraud["attempts"] else 0.0
            )
            honest_emission = emission * (
                1.0 - min(0.20, 0.20 * escape_ratio)
            )
            intended_sell = (
                honest_emission * miner_sell_fraction
                + min(
                    state.deferred_sell_myc,
                    honest_emission * 0.25,
                )
            )

            depth_x = math.sqrt(x * y) / math.sqrt(
                BASE_POOL_MYC * BASE_POOL_MUSD
            )
            normal_trade_max = sim4x.dynamic_trade_max_myc(
                x,
                max_total_deviation=policy.trade_impact_limit,
                fee=AMM_FEE,
                volatility_multiplier=1.0,
            )
            trade_max = normal_trade_max * policy_out["trade_scale"]
            sold = min(intended_sell, trade_max)
            if sold <= 1e-12 and intended_sell > 0:
                counters["treasury_sell_paused_days"] += 1
            state.deferred_sell_myc = max(
                0.0,
                state.deferred_sell_myc
                + honest_emission * miner_sell_fraction
                - sold
            )
            if sold > 0:
                x, y, _ = base.cp_swap_x_for_y(
                    x, y, sold, AMM_FEE
                )
                external_l, protocol_l = rebase_lp_tokens(
                    x, y, external_l, protocol_l
                )

            totals["service_revenue_musd"] += finalized_revenue
            totals["worker_income_musd"] += effective_worker_income
            totals["validator_income_musd"] += validator_income
            totals["lp_budget_musd"] += lp_budget
            totals["general_reserve_contrib_musd"] += general_contrib
            totals["wsr_contrib_musd"] += wsr_contrib
            totals["wsr_payout_musd"] += wsr_payout
            totals["emission_myc"] += emission
            totals["sold_myc"] += sold
        else:
            effective_worker_income = 0.0
            emission = 0.0

        income_per_miner = (
            effective_worker_income / max(miners, 1)
        )
        # Smooth churn perception over a week: a one-day partition does not
        # make workers immediately abandon the network.
        finalized_income_trailing.append(income_per_miner)
        if len(finalized_income_trailing) > 7:
            finalized_income_trailing.pop(0)
        perceived_income = statistics.mean(finalized_income_trailing)

        miners, exits, entrants = update_miners_v3(
            rng, miners, target_miners,
            perceived_income, policy,
        )
        resize_vectors(
            reputations, ages, miner_risks, miners
        )
        min_miners = min(min_miners, miners)
        max_miners = max(max_miners, miners)

        spot = y / x
        update_market_volatility(state, spot)

        depth_x = math.sqrt(x * y) / math.sqrt(
            BASE_POOL_MYC * BASE_POOL_MUSD
        )
        min_depth = min(min_depth, depth_x)

        current_worker_income = (
            effective_worker_income / max(miners, 1)
        )
        current_reserve_target = (
            BASE_WORKER_INCOME_MUSD_DAY
            * policy.worker_floor_ratio
            * miners * policy.reserve_target_days
        )
        risks = compute_risks(
            policy, state,
            service_income_per_miner=current_worker_income,
            worker_floor=BASE_WORKER_INCOME_MUSD_DAY * policy.worker_floor_ratio,
            reserve_target=current_reserve_target,
            liquidity_depth_x=depth_x,
            finality_ok=finality_ok,
            online_validators=online,
            quorum=quorum,
        )
        for i, value in enumerate(asdict(risks).values()):
            risk_sums[i] += value

        controller, bottleneck, factors = v2.daily_controller(
            scale, execution_x, miners,
            raw_service_revenue, x, y, finality_ok
        )
        bottleneck_counts[bottleneck] = (
            bottleneck_counts.get(bottleneck, 0) + 1
        )
        if finality_ok:
            controller_active.append(controller)

        if day in (1, 7, 30, 90, 180, 365) or day == days:
            snapshots.append({
                "day": day,
                "miners": miners,
                "demand_factor": demand_factor,
                "finality_ok": finality_ok,
                "liquidity_depth_x": depth_x,
                "spot_musd_per_myc": spot,
                "wsr_musd": state.worker_stability_reserve_musd,
                "general_reserve_musd": state.general_reserve_musd,
                "deferred_sell_myc": state.deferred_sell_myc,
                "emission_myc": emission,
                "risks": asdict(risks),
                "kernel": policy_out,
                "controller_x": controller,
                "bottleneck": bottleneck,
            })

    fraud_detection = (
        counters["fraud_detected"] / counters["fraud_attempts"]
        if counters["fraud_attempts"] else 1.0
    )
    finality_availability = finality_ok_days / days
    final_depth = math.sqrt(x * y) / math.sqrt(
        BASE_POOL_MYC * BASE_POOL_MUSD
    )
    final_spot = y / x
    wsr_target_final = (
        BASE_WORKER_INCOME_MUSD_DAY
        * policy.worker_floor_ratio
        * miners * policy.reserve_target_days
    )

    safety_violations = 0
    if totals["emission_myc"] > EMISSION_CEILING_MYC_DAY * finality_ok_days + 1e-6:
        safety_violations += 1

    fraud_gate = (
        counters["fraud_attempts"] < 20
        or fraud_detection >= 0.50
    )
    survived = (
        safety_violations == 0
        and finality_availability >= 0.95
        and final_depth >= 0.50
        and min_miners >= max(1, int(target_miners * 0.40))
        and fraud_gate
        and math.isfinite(final_spot)
        and final_spot > 0
    )

    return {
        "scale": scale,
        "profile": profile.name,
        "seed": seed,
        "policy": asdict(policy),
        "survived": survived,
        "safety_violations": safety_violations,
        "finality_availability": finality_availability,
        "miners": {
            "target": target_miners,
            "final": miners,
            "minimum": min_miners,
            "maximum": max_miners,
        },
        "liquidity": {
            "final_depth_x": final_depth,
            "minimum_depth_x": min_depth,
            "final_spot_musd_per_myc": final_spot,
            "external_lp_share": (
                external_l / max(external_l + protocol_l, 1e-12)
            ),
            "protocol_lp_share": (
                protocol_l / max(external_l + protocol_l, 1e-12)
            ),
        },
        "reserves": {
            "worker_stability_reserve_musd":
                state.worker_stability_reserve_musd,
            "worker_stability_target_musd": wsr_target_final,
            "worker_stability_coverage_fraction":
                state.worker_stability_reserve_musd
                / max(wsr_target_final, 1e-12),
            "general_reserve_musd": state.general_reserve_musd,
        },
        "fraud": {
            "attempts": counters["fraud_attempts"],
            "detected": counters["fraud_detected"],
            "escaped": counters["fraud_escaped"],
            "detection_rate": fraud_detection,
            "audits": counters["audits"],
            "slashed": counters["slashed"],
        },
        "povc": {
            "emitted_myc_total": totals["emission_myc"],
            "average_emission_myc_per_day":
                totals["emission_myc"] / days,
            "sold_myc_total": totals["sold_myc"],
            "deferred_sell_myc": state.deferred_sell_myc,
        },
        "economics": {
            **totals,
            "average_finalized_service_revenue_musd_per_day":
                totals["service_revenue_musd"] / days,
        },
        "counters": counters,
        "risk_average": {
            "r_worker": risk_sums[0] / days,
            "r_liquidity": risk_sums[1] / days,
            "r_fraud": risk_sums[2] / days,
            "r_partition": risk_sums[3] / days,
        },
        "controller": {
            "active_median_x": (
                statistics.median(controller_active)
                if controller_active else 0.0
            ),
            "active_p05_x": (
                v2.quantile(controller_active, 0.05)
                if controller_active else 0.0
            ),
            "bottleneck_day_counts": bottleneck_counts,
        },
        "snapshots": snapshots,
    }


def aggregate(rows):
    return {
        "trials": len(rows),
        "survival_rate": sum(r["survived"] for r in rows) / len(rows),
        "safety_violation_rate":
            sum(r["safety_violations"] > 0 for r in rows) / len(rows),
        "finality_availability": {
            "median": statistics.median(
                r["finality_availability"] for r in rows
            ),
            "p05": v2.quantile(
                [r["finality_availability"] for r in rows], 0.05
            ),
        },
        "final_liquidity_depth_x": {
            "median": statistics.median(
                r["liquidity"]["final_depth_x"] for r in rows
            ),
            "p05": v2.quantile(
                [r["liquidity"]["final_depth_x"] for r in rows], 0.05
            ),
        },
        "minimum_miners": {
            "median": statistics.median(
                r["miners"]["minimum"] for r in rows
            ),
            "p05": v2.quantile(
                [r["miners"]["minimum"] for r in rows], 0.05
            ),
        },
        "fraud_detection_rate": {
            "median": statistics.median(
                r["fraud"]["detection_rate"] for r in rows
            ),
            "p05": v2.quantile(
                [r["fraud"]["detection_rate"] for r in rows], 0.05
            ),
        },
        "average_emission_myc_per_day": {
            "median": statistics.median(
                r["povc"]["average_emission_myc_per_day"] for r in rows
            ),
            "p95": v2.quantile(
                [r["povc"]["average_emission_myc_per_day"] for r in rows],
                0.95,
            ),
        },
        "wsr_coverage_fraction": {
            "median": statistics.median(
                r["reserves"]["worker_stability_coverage_fraction"]
                for r in rows
            ),
            "p05": v2.quantile(
                [r["reserves"]["worker_stability_coverage_fraction"]
                 for r in rows], 0.05
            ),
        },
        "wsr_empty_days": {
            "median": statistics.median(
                r["counters"]["wsr_empty_days"] for r in rows
            ),
            "p95": v2.quantile(
                [r["counters"]["wsr_empty_days"] for r in rows], 0.95
            ),
        },
        "controller_active_median_x": {
            "median": statistics.median(
                r["controller"]["active_median_x"] for r in rows
            ),
            "p05": v2.quantile(
                [r["controller"]["active_median_x"] for r in rows], 0.05
            ),
        },
        "service_revenue_total_musd": {
            "median": statistics.median(
                r["economics"]["service_revenue_musd"] for r in rows
            ),
        },
    }


def evaluate_policy(policy: DefensePolicy, *, scale=4, days=365,
                    trials=40, seed=1000,
                    profiles=("normal", "demand_shock",
                              "liquidity_run", "fraud", "combined")):
    output = {}
    for pidx, name in enumerate(profiles):
        profile = v2.PROFILES[name]
        rows = [
            simulate_trial(
                scale, profile, policy,
                days=days,
                seed=seed + pidx * 100_003 + i * 9973,
            )
            for i in range(trials)
        ]
        output[name] = aggregate(rows)

    weights = {
        "combined": 0.40,
        "demand_shock": 0.20,
        "liquidity_run": 0.15,
        "fraud": 0.15,
        "normal": 0.10,
    }
    survival_component = sum(
        weights[n] * output[n]["survival_rate"]
        for n in weights if n in output
    )
    inflation = statistics.mean(
        output[n]["average_emission_myc_per_day"]["median"]
        / EMISSION_CEILING_MYC_DAY
        for n in output
    )
    reserve_empty = statistics.mean(
        output[n]["wsr_empty_days"]["median"] / days
        for n in output
    )
    safety = max(
        output[n]["safety_violation_rate"] for n in output
    )
    score = (
        survival_component
        - 0.04 * inflation
        - 0.08 * reserve_empty
        - 10.0 * safety
    )
    return {
        "score": score,
        "survival_component": survival_component,
        "inflation_fraction": inflation,
        "reserve_empty_fraction": reserve_empty,
        "safety_violation_rate": safety,
        "profiles": output,
    }


def sample_policy(rng: random.Random) -> DefensePolicy:
    return DefensePolicy(
        worker_floor_ratio=rng.choice([0.50, 0.60, 0.70]),
        reserve_target_days=rng.choice([7, 14, 21, 28]),
        bootstrap_wsr_share=rng.choice([0.08, 0.10, 0.12, 0.15]),
        maintenance_wsr_share=rng.choice([0.03, 0.05, 0.07]),
        lp_share_normal=rng.choice([0.04, 0.05, 0.06]),
        lp_share_max=rng.choice([0.12, 0.15, 0.18, 0.20]),
        audit_base=rng.choice([0.10, 0.15, 0.20]),
        risk_memory_lambda=rng.choice([0.65, 0.80, 0.90]),
        churn_sensitivity=rng.choice([0.45, 0.60, 0.75, 0.90]),
        trade_impact_limit=rng.choice([0.0075, 0.0100, 0.0125]),
        trade_volatility_lambda=rng.choice([2.0, 4.0, 6.0]),
        receipt_ttl_days=rng.choice([7, 14, 21]),
        recovery_backlog_multiple=rng.choice([1.25, 1.50, 2.00]),
        emission_liquidity_brake=rng.choice([0.40, 0.55, 0.70]),
        emission_partition_brake=rng.choice([0.15, 0.25, 0.40]),
    )


def policy_search(*, candidates=80, search_trials=20,
                  confirm_trials=100, days=365,
                  scale=4, seed=20260927,
                  max_temp_c=78.0, checkpoint=None):
    rng = random.Random(seed)
    baseline = DefensePolicy()
    candidate_policies = [baseline]
    seen = {json.dumps(asdict(baseline), sort_keys=True)}
    while len(candidate_policies) < candidates:
        p = sample_policy(rng)
        key = json.dumps(asdict(p), sort_keys=True)
        if key not in seen:
            seen.add(key)
            candidate_policies.append(p)

    scored = []
    for idx, p in enumerate(candidate_policies):
        gate=thermal_gate(max_temp_c=max_temp_c)
        result = evaluate_policy(
            p, scale=scale, days=days,
            trials=search_trials,
            seed=seed + idx * 1_000_003,
        )
        scored.append({
            "policy": p,
            "search": result,
            "thermal_gate_before": gate,
        })
        if checkpoint is not None:
            cp={
                "kind":"MYCELIUM_4X_V3_POLICY_SEARCH_CHECKPOINT",
                "completed_candidates":idx+1,
                "requested_candidates":candidates,
                "best_so_far":{
                    "policy":asdict(max(scored,key=lambda x:x["search"]["score"])["policy"]),
                    "score":max(x["search"]["score"] for x in scored),
                },
            }
            Path(checkpoint).write_text(json.dumps(cp,indent=2,sort_keys=True)+"\\n")
    scored.sort(key=lambda x: x["search"]["score"], reverse=True)

    finalists = scored[:min(5, len(scored))]
    confirmed = []
    for rank, item in enumerate(finalists):
        p = item["policy"]
        thermal_gate(max_temp_c=max_temp_c)
        result = evaluate_policy(
            p, scale=scale, days=days,
            trials=confirm_trials,
            seed=seed + 90_000_000 + rank * 2_000_003,
        )
        confirmed.append({
            "policy": asdict(p),
            "search_score": item["search"]["score"],
            "confirmation": result,
        })
    confirmed.sort(
        key=lambda x: x["confirmation"]["score"], reverse=True
    )
    return {
        "kind": "MYCELIUM_4X_V3_POLICY_SEARCH",
        "scale": scale,
        "days": days,
        "candidate_count": candidates,
        "search_trials_per_profile": search_trials,
        "confirmation_trials_per_profile": confirm_trials,
        "objective": (
            "weighted survival across combined/demand/liquidity/fraud/normal "
            "minus bounded inflation and WSR depletion penalties"
        ),
        "hard_constraints": {
            "emission_ceiling_myc_day": 1000,
            "no_quorum_no_emission": True,
            "unbacked_musd": 0,
            "safety_violation_required": 0,
        },
        "best": confirmed[0],
        "finalists": confirmed,
    }


def main():
    ap = argparse.ArgumentParser(
        description="Mycelium 4X v3 Adaptive Defense Kernel"
    )
    sub = ap.add_subparsers(dest="command", required=True)

    sim = sub.add_parser("simulate")
    sim.add_argument("--profile", choices=sorted(v2.PROFILES), default="combined")
    sim.add_argument("--scale", type=int, default=4)
    sim.add_argument("--days", type=int, default=365)
    sim.add_argument("--trials", type=int, default=200)
    sim.add_argument("--seed", type=int, default=20260927)
    sim.add_argument("--out", type=Path)

    search = sub.add_parser("search")
    search.add_argument("--scale", type=int, default=4)
    search.add_argument("--days", type=int, default=365)
    search.add_argument("--candidates", type=int, default=80)
    search.add_argument("--search-trials", type=int, default=20)
    search.add_argument("--confirm-trials", type=int, default=100)
    search.add_argument("--seed", type=int, default=20260927)
    search.add_argument("--max-temp-c", type=float, default=78.0)
    search.add_argument("--checkpoint", type=Path)
    search.add_argument("--out", type=Path)

    args = ap.parse_args()
    if args.command == "simulate":
        policy = DefensePolicy()
        profile = v2.PROFILES[args.profile]
        rows = [
            simulate_trial(
                args.scale, profile, policy,
                days=args.days,
                seed=args.seed + i * 9973,
            )
            for i in range(args.trials)
        ]
        report = {
            "kind": "MYCELIUM_4X_V3_ADAPTIVE_DEFENSE_SIM",
            "policy": asdict(policy),
            "profile": args.profile,
            "aggregate": aggregate(rows),
            "representative_trial": rows[0],
        }
    else:
        report = policy_search(
            candidates=args.candidates,
            search_trials=args.search_trials,
            confirm_trials=args.confirm_trials,
            days=args.days,
            scale=args.scale,
            seed=args.seed,
            max_temp_c=args.max_temp_c,
            checkpoint=args.checkpoint,
        )

    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.out:
        if not args.out.is_absolute():
            raise SystemExit("--out must be absolute")
        args.out.write_text(payload)
    print(payload, end="")


if __name__ == "__main__":
    main()
