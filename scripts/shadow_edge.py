#!/usr/bin/env python3
"""Read-only 7-day measurement of USDC->WETH->USDC spread across Base DEX quoters.

Only eth_call/eth_blockNumber. No keys, no signing, no broadcast, no repo state.

  shadow_edge.py selftest          # quoters answer sanely?
  shadow_edge.py run [--days 7]    # sample every INTERVAL s, append JSONL
  shadow_edge.py report            # what the samples say vs the R$ target

Env: BASE_RPC_URL, OUT, INTERVAL (s), GAS_USD, FLASH_FEE_BPS, BRL_PER_USD, TARGET_BRL.
"""
import json, os, statistics, sys, time, urllib.request

RPC = os.environ.get("BASE_RPC_URL", "https://mainnet.base.org")
OUT = os.path.expanduser(os.environ.get("OUT", "~/.mycelium/shadow/edge.jsonl"))
INTERVAL = float(os.environ.get("INTERVAL", "12"))
GAS_USD = float(os.environ.get("GAS_USD", "0.05"))  # assumption: Base gas + L1 data fee for a 2-swap flash tx
FEE_BPS = float(os.environ.get("FLASH_FEE_BPS", "0"))  # unverified: crate says both 0% and 5 bps
BRL = float(os.environ.get("BRL_PER_USD", "5.5"))
TARGET_BRL = float(os.environ.get("TARGET_BRL", "10000"))
SIZES = [100, 1000, 10000]  # USDC

USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
WETH = "0x4200000000000000000000000000000000000006"
UNI_QUOTER = "0x3d4e44Eb1374240CE5F1B871ab261CD16335B76a"  # Uniswap V3 QuoterV2
AERO_ROUTER = "0xcF77a3Ba9A5CA399B7c97c74d54e5b1Beb874E43"
AERO_FACTORY = "0x420DD381b31aEf6683db6B902084cB0FFECe40Da"


def w(x): return f"{x:064x}"
def a(s): return s[2:].lower().rjust(64, "0")


def quote_call(venue, tin, tout, amt):
    if venue.startswith("uni"):
        data = "0xc6a5026a" + a(tin) + a(tout) + w(amt) + w(int(venue[3:])) + w(0)
        return {"to": UNI_QUOTER, "data": data}
    data = "0x5509a1ac" + w(amt) + w(64) + w(1) + a(tin) + a(tout) + w(0) + a(AERO_FACTORY)
    return {"to": AERO_ROUTER, "data": data}


def decode(venue, res):
    h = res[2:]
    if len(h) < 64: return None
    # QuoterV2 returns amountOut first; Aerodrome returns uint256[] so amountOut is the last word.
    v = int(h[:64], 16) if venue.startswith("uni") else int(h[-64:], 16)
    return v or None


VENUES = ["uni500", "uni3000", "aero"]  # aero = volatile WETH/USDC pool via Router


def rpc(reqs):
    r = urllib.request.Request(RPC, json.dumps(reqs).encode(),
                               {"content-type": "application/json", "user-agent": "mycelium-shadow/1"})
    out = json.load(urllib.request.urlopen(r, timeout=30))
    return sorted(out, key=lambda x: x["id"])


def calls(block, items):
    """items: [(venue, tin, tout, amt)] -> list of amountOut or None, one batched request."""
    reqs = [{"jsonrpc": "2.0", "id": i, "method": "eth_call", "params": [quote_call(*it), block]}
            for i, it in enumerate(items)]
    return [decode(it[0], r["result"]) if "result" in r else None for it, r in zip(items, rpc(reqs))]


def sample():
    blk = int(rpc([{"jsonrpc": "2.0", "id": 0, "method": "eth_blockNumber", "params": []}])[0]["result"], 16)
    tag = hex(blk)
    legs = [(v, s) for s in SIZES for v in VENUES]
    weth = calls(tag, [(v, USDC, WETH, s * 10**6) for v, s in legs])
    back = [(vb, sv, s, ws) for (vb, s), ws in zip(legs, weth) if ws for sv in VENUES if sv != vb]
    outs = calls(tag, [(sv, WETH, USDC, ws) for vb, sv, s, ws in back])
    return {"t": int(time.time()), "block": blk,
            "r": [[s, vb, sv, o] for (vb, sv, s, _), o in zip(back, outs) if o]}


def run(days):
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    end, backoff = time.time() + days * 86400, 0
    with open(OUT, "a", buffering=1) as f:
        while time.time() < end:
            t0 = time.time()
            try:
                f.write(json.dumps(sample()) + "\n"); backoff = 0
            except Exception as e:  # network/rate-limit: record and back off, never crash the 7 days
                f.write(json.dumps({"t": int(t0), "err": str(e)[:120]}) + "\n")
                backoff = min(max(backoff * 2, 5), 300)
            time.sleep(max(INTERVAL - (time.time() - t0), 0) + backoff)


def net_usd(size, out_raw): return out_raw / 1e6 - size - GAS_USD - size * FEE_BPS / 1e4


def report():
    rows = [json.loads(l) for l in open(OUT)]
    ok = [r for r in rows if "r" in r]
    if not ok: sys.exit("no samples yet")
    errs = len(rows) - len(ok)
    days = len(ok) * INTERVAL / 86400
    print(f"samples={len(ok)} errors={errs} covered~{days:.2f}d  gas=${GAS_USD} flash_fee={FEE_BPS}bps")
    for s in SIZES:
        eps, cur, pos = [], [], 0
        gross = []
        for r in ok:
            best = max(((net_usd(s, o), (vb, sv), (o / 1e6 - s) / s * 1e4) for sz, vb, sv, o in r["r"] if sz == s),
                       default=None)
            if best: gross.append(best[2])
            if best and best[0] > 0 and (not cur or r["t"] - cur[-1][0] <= 3 * INTERVAL):
                cur.append((r["t"], best[0])); pos += 1
            elif best and best[0] > 0:
                eps.append(cur); cur = [(r["t"], best[0])]; pos += 1
            elif cur:
                eps.append(cur); cur = []
        if cur: eps.append(cur)
        persist = [e for e in eps if len(e) >= 2]  # still there >= one interval later
        scale = 30 / days if days else 0
        up, pl = (sum(max(n for _, n in e) for e in x) * scale * BRL for x in (eps, persist))
        print(f"\n${s:>6} loan | best gross {max(gross, default=float('nan')):+.1f} bps, median {statistics.median(gross) if gross else float('nan'):+.1f} bps"
              f" | net>0 in {pos}/{len(ok)} samples, {len(eps)} episodes ({len(persist)} lasting >=1 interval)")
        print(f"         upper bound R$/month: {up:,.0f} (every episode captured)  |  persistent only: {pl:,.0f}  |  target R${TARGET_BRL:,.0f}")
    print("\nUpper bound assumes you land first on every edge seen. Quotes are block-start state; competing bots are not modeled.")


def selftest():
    for v in VENUES:
        q = calls("latest", [(v, USDC, WETH, 1000 * 10**6)])[0]
        b = calls("latest", [(v, WETH, USDC, q)])[0] if q else None
        assert q and b and 970e6 < b < 1000.5e6, f"{v}: bad round trip {q} -> {b}"
        print(f"{v:8} ok  1000 USDC -> {q/1e18:.5f} WETH -> {b/1e6:.2f} USDC")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "selftest": selftest()
    elif cmd == "run": run(float(sys.argv[sys.argv.index("--days") + 1]) if "--days" in sys.argv else 7)
    elif cmd == "report": report()
    else: sys.exit(__doc__)
