# RV0 Revenue Validation

## Objective

Verify the first externally paid job. MYC prices, simulated settlements and
internal work do not count as revenue.

Income_user = PaidDemand * WorkerShare * EconomicCapacityShare

RV0 validates only the first term: PaidDemand > 0 from an external customer.

## State machine

    JobRequest
       |
    PaymentIntent (Base block anchor)
       |
    verified local WorkReceipt
       |
    external USDC Transfer after anchor
       |
    read-only Base verifier
       |
    SettlementReceipt
       |
    Revenue Ledger
       |
    RV0 PASS

Work and payment may happen in either order after `JobRequest`. Final
settlement requires both a verified work receipt and a valid external payment.

## What does not count

- internal Mycelium jobs;
- simulated mUSD;
- MYC emission/rewards;
- a user-provided transaction hash that was not verified;
- a USDC transfer to another recipient;
- an amount different from the exact job price;
- a transfer at or before the job PaymentIntent anchor block;
- a reused transaction hash.

## Evidence

The local ledger is append-only JSONL with a BLAKE3 hash chain. rv-status, revenue and all normal ledger reads fail if the chain does not validate.

This is tamper-evident local evidence, not an external audit or immutable public anchor. A later milestone can periodically anchor the ledger head into Mycelium consensus.

## Current settlement adapter

Base mainnet USDC, read-only through the local Mycelium gateway.

The adapter has no private-key access, signing API or broadcast method.

## Promotion rules

    PRE-RV0 -> RV0: >= 1 externally paid + verified + settled job
    RV0 -> RV1: >= 10 mUSD/day average over a complete 30-day window
    RV1 -> RV2: >= 100 mUSD/day average over a complete 30-day window
    RV2 -> RV3: >= 500 mUSD/day average over a complete 30-day window
    RV3 -> RV4: >= 2000 mUSD/day average over a complete 30-day window

Simulation never promotes these states.
