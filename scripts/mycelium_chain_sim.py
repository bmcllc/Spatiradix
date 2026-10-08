#!/usr/bin/env python3
"""Local deterministic simulation for Mycelium Chain economics/consensus.

No network access, no external RPC, no real transactions.
All prices/reserves are hypothetical simulation inputs.
"""
from __future__ import annotations

import argparse
import json
import math
import random
import statistics
from dataclasses import dataclass, asdict


def quorum(n: int) -> int:
    if n < 1:
        raise ValueError("validators must be >= 1")
    return math.floor(2 * n / 3) + 1


def byzantine_tolerance(n: int) -> int:
    return max(0, math.floor((n - 1) / 3))


def lognormal_params(median_ms: float, p95_ms: float):
    if not (0 < median_ms < p95_ms):
        raise ValueError("latency median must be >0 and < p95")
    mu = math.log(median_ms)
    sigma = (math.log(p95_ms) - mu) / 1.6448536269514722
    return mu, sigma


def latency_sim(n: int, *, trials=5000, median_ms=2.0, p95_ms=8.0,
                verify_ms=0.5, aggregate_ms=1.0, seed=42):
    rng = random.Random(seed + n)
    mu, sigma = lognormal_params(median_ms, p95_ms)
    q = quorum(n)
    samples = []
    for _ in range(trials):
        arrivals = []
        for _v in range(n):
            out = rng.lognormvariate(mu, sigma)
            back = rng.lognormvariate(mu, sigma)
            arrivals.append(out + verify_ms + back + verify_ms)
        arrivals.sort()
        # QC forms at quorum-th vote, then is broadcast once.
        qc = arrivals[q - 1] + aggregate_ms
        qc += rng.lognormvariate(mu, sigma) + verify_ms
        samples.append(qc)
    samples.sort()
    def pct(p):
        idx = min(len(samples) - 1, max(0, int(round((len(samples)-1) * p))))
        return samples[idx]
    return {
        "validators": n,
        "quorum": q,
        "byzantine_tolerance": byzantine_tolerance(n),
        "lan_model_assumptions": {
            "one_way_latency_median_ms": median_ms,
            "one_way_latency_p95_ms": p95_ms,
            "signature_verify_ms": verify_ms,
            "qc_aggregate_ms": aggregate_ms,
            "trials": trials,
        },
        "qc_latency_ms": {
            "median": pct(0.50),
            "p95": pct(0.95),
            "p99": pct(0.99),
        },
    }


@dataclass
class Worker:
    name: str
    quantity: float
    reliability: float
    verifiability: float
    availability_value: float

    @property
    def score(self):
        return (self.quantity * self.reliability *
                self.verifiability * self.availability_value)


def povc_epoch(workers, emission_myc=100.0):
    total = sum(w.score for w in workers)
    if total <= 0:
        raise ValueError("total contribution score must be > 0")
    return {
        "epoch_emission_myc": emission_myc,
        "workers": [
            {
                **asdict(w),
                "score": w.score,
                "reward_myc": emission_myc * w.score / total,
            }
            for w in workers
        ],
        "score_total": total,
        "reward_total_myc": emission_myc,
    }


def audit_risk():
    out = {}
    for p in (0.05, 0.10, 0.40, 0.90):
        out[f"audit_{int(p*100)}pct"] = {
            "undetected_after_1_fraud": (1-p),
            "undetected_after_10_frauds": (1-p) ** 10,
            "undetected_after_100_frauds": (1-p) ** 100,
        }
    return out


def cp_swap_x_for_y(x, y, dx, fee=0.003):
    dx_eff = dx * (1.0 - fee)
    dy = y - (x * y) / (x + dx_eff)
    return x + dx, y - dy, dy


def cp_swap_y_for_x(x, y, dy, fee=0.003):
    dy_eff = dy * (1.0 - fee)
    dx = x - (x * y) / (y + dy_eff)
    return x - dx, y + dy, dx


def dex_trade_table(x=100_000.0, y=10_000.0, fee=0.003):
    spot = y / x
    rows = []
    for amount in (100, 1_000, 5_000, 10_000):
        _, _, out = cp_swap_x_for_y(x, y, float(amount), fee)
        ideal = amount * spot
        rows.append({
            "sell_myc": amount,
            "receive_musd": out,
            "average_price_musd_per_myc": out / amount,
            "deviation_from_initial_spot_fraction": 1.0 - out / ideal,
        })
    return {
        "external_lp_assumption": {
            "myc_reserve": x,
            "musd_reserve": y,
            "initial_spot_musd_per_myc": spot,
            "fee_fraction": fee,
        },
        "trades": rows,
    }


def required_lp_for_sell(sell_myc, spot, max_deviation=0.01, fee=0.003):
    # Effective execution / spot = (1-fee)*x/(x+(1-fee)*amount)
    f = 1.0 - fee
    target = 1.0 - max_deviation
    denom = f - target
    if denom <= 0:
        return None
    x = target * f * sell_myc / denom
    return {
        "sell_myc": sell_myc,
        "max_total_deviation_fraction": max_deviation,
        "required_myc_reserve_approx": x,
        "required_musd_reserve_approx": x * spot,
    }


def market_flow_sim(*, days=30, daily_service_demand_musd=500.0,
                    service_buyback_share=0.10,
                    daily_povc_emission_myc=1000.0,
                    miner_sell_fraction=0.50,
                    x=100_000.0, y=10_000.0, fee=0.003):
    initial_price = y / x
    history = []
    for day in range(1, days + 1):
        # Demand-driven buy: service activity routes a fraction of mUSD into MYC.
        buy_musd = daily_service_demand_musd * service_buyback_share
        x, y, bought_myc = cp_swap_y_for_x(x, y, buy_musd, fee)

        # Emission-driven sell: miners sell a configured fraction of daily rewards.
        sold_myc = daily_povc_emission_myc * miner_sell_fraction
        x, y, received_musd = cp_swap_x_for_y(x, y, sold_myc, fee)

        history.append({
            "day": day,
            "spot_musd_per_myc": y / x,
            "myc_reserve": x,
            "musd_reserve": y,
            "service_buy_musd": buy_musd,
            "myc_bought_by_service_flow": bought_myc,
            "miner_sell_myc": sold_myc,
            "musd_received_by_miners": received_musd,
        })

    break_even_demand = (
        daily_povc_emission_myc * miner_sell_fraction * initial_price /
        max(service_buyback_share, 1e-12)
    )
    return {
        "assumptions": {
            "days": days,
            "daily_service_demand_musd": daily_service_demand_musd,
            "service_buyback_share": service_buyback_share,
            "daily_povc_emission_myc": daily_povc_emission_myc,
            "miner_sell_fraction": miner_sell_fraction,
            "amm_fee_fraction": fee,
            "initial_myc_reserve": 100_000.0,
            "initial_musd_reserve": 10_000.0,
            "initial_spot_musd_per_myc": initial_price,
        },
        "static_first_order_break_even_service_demand_musd_per_day":
            break_even_demand,
        "final": history[-1],
        "history": history,
        "warning": (
            "Mechanical AMM simulation only. It assumes no external arbitrage, "
            "no other buyers/sellers and fixed behavior; it is not a price forecast."
        ),
    }


def stablecoin_demo(external_reserve_deposit=10_000.0):
    # Protocol treasury starts at zero. Reserve appears only when an external
    # holder deposits mock USDC in this simulation.
    protocol_initial_reserve = 0.0
    reserve = protocol_initial_reserve + external_reserve_deposit
    mint = external_reserve_deposit
    supply = mint
    return {
        "protocol_initial_external_capital": 0.0,
        "external_mock_usdc_deposit": external_reserve_deposit,
        "musd_minted": mint,
        "reserve_after": reserve,
        "musd_supply_after": supply,
        "reserve_ratio": reserve / supply if supply else None,
        "unbacked_musd": max(0.0, supply - reserve),
        "offline_rule": (
            "Transfers may continue locally while disconnected; new external-"
            "reserve mint/burn must fail closed unless reserve proof is available."
        ),
        "warning": (
            "This is local accounting simulation, not evidence of real USD backing."
        ),
    }


def build_report(days=30):
    workers = [
        Worker("compute", 1.00, 0.990, 0.980, 1.20),
        Worker("storage", 0.80, 0.995, 1.000, 1.00),
        Worker("bandwidth", 1.10, 0.970, 0.950, 1.30),
        Worker("replication", 0.60, 0.999, 0.990, 1.40),
    ]
    consensus = [latency_sim(n) for n in (4, 7, 16, 32, 64)]
    dex = dex_trade_table()
    dex["liquidity_target_for_1000_myc_sell_at_1pct"] = required_lp_for_sell(
        1_000, 0.10, 0.01
    )
    flow_scenarios = {
        f"demand_{d}_musd_per_day": market_flow_sim(
            days=days, daily_service_demand_musd=float(d)
        )
        for d in (100, 500, 1000)
    }
    return {
        "kind": "MYCELIUM_CHAIN_LOCAL_SIMULATION",
        "version": 1,
        "real_money": False,
        "external_network_required": False,
        "consensus": consensus,
        "povc": povc_epoch(workers),
        "audit": audit_risk(),
        "stablecoin": stablecoin_demo(),
        "dex": dex,
        "market_flow_scenarios": flow_scenarios,
        "core_invariants": {
            "consensus_is_not_mining": True,
            "myc_is_mined_by_verified_contribution": True,
            "musd_is_never_mined": True,
            "musd_unbacked_mint_allowed": False,
            "protocol_initial_external_capital_required": 0.0,
            "external_liquidity_required_for_real_conversion": True,
        },
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=30)
    ap.add_argument("--out")
    args = ap.parse_args()
    if not 1 <= args.days <= 3650:
        raise SystemExit("days out of range")
    report = build_report(args.days)
    payload = json.dumps(report, indent=2, sort_keys=True)
    if args.out:
        p = __import__("pathlib").Path(args.out)
        if not p.is_absolute():
            raise SystemExit("--out must be absolute")
        p.write_text(payload + "\n")
    print(payload)


if __name__ == "__main__":
    main()
