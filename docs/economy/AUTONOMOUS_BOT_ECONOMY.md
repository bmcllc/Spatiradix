# Mycelium Autonomous Bot Economy

## Objective

Build a machine-to-machine economy in which autonomous agents buy bounded Mycelium work to pursue opportunities in external systems. Internal bot spending is activity, never new revenue. Only externally verified realized value can promote Autonomous Revenue Validation (ARV).

A proposed offline service economy is described in [Mycelium-ECO soberano](MYCELIUM_ECO_SOBERANO.md). It separates local service credits and measured resource benefits from external revenue; that local circuit is not implemented and does not change the ARV/NEV invariants below.

## Core flow

    S1 / TERR / other agents
            |
            v
    OpportunityCandidate
            |
            v
    Economic Orchestrator
       ACCEPT / REJECT
            |
            v
        JobIntent
            |
            v
    internal JobRequest
            |
            v
       WorkReceipt
            |
            v
    external outcome
            |
            v
    verified ExternalValueReceipt
            |
            v
       ARV / accounting

On the read side every number passes through the verified view, which derives
the boundary from stored evidence, checks it against a pinned provider and
re-reads the cited transaction:

    on-disk ledgers  ->  VerifiedEconomyView  ->  ARV / verified NEV
    (diagnostics)        VerifiedRevenueView  ->  RV / paid demand
                         reinvestment budget

    TrustedNEV = VerifyChain(VerifyPolicy(DeriveBoundary(Evidence)))

## Implemented invariants

- Internal JobRequest has internal_work=true.
- Internal bot spending never increases PaidDemand or NetExternalValue.
- A bot cannot self-assert proof_verified through the CLI.
- Opportunity spending is bounded by per-job and daily agent budgets.
- Economic acceptance requires robust modeled net value above a configured edge.
- S1 shadow scans are opportunities only; profitIsReal=true is refused by the shadow importer.
- S1 modeled beneficiary profit is not double-charged for network cost already included by S1.
- Realized S1 value requires a separate Base reconciliation path.
- S1 realized outcome verification requires configured executor, canonical Base tx/block, sponsor identity, SharedExecution event, exact beneficiary and exact USDC beneficiary transfer.
- Only beneficiary USDC actually paid by the executor is booked as external value.
- Reused external source/proof identifiers are rejected.
- Verified external losses reduce NetExternalValue; they cannot be hidden by the positive-event path.
- TERR remains passive-only and can create only bounded validation/backtest/data_transform research jobs.
- Adaptive reinvestment can use only verified positive net external value above a reserve floor.
- Liquidity, fraud, partition, demand, worker and thermal signals can only reduce automatic reinvestment.
- ARV1-ARV4 require a complete 30-day external-value window.
- Revenue, autonomous, TERR research and reinvestment ledgers are hash-chained and fail closed on tampering.
- A stored `proof_verified: true` is a claim, not an authority input. It stays in the serialized record for diagnostics and for `autonomy-audit`, and no economic path reads it.
- Every economic number is re-derived on read: hash chain, the receipt's own validation rules, the boundary derived from stored `BoundaryEvidence` against the current controlled-address registry, and the cited transaction re-read from a pinned provider.
- `TrustMode` is always reported. `unverified` can never promote a level and can never fund a commitment; `provider_pinned` is the only mode that can.
- The dev-only provider override can drive a verifier but can never attest: it authenticates nothing, so a number attributed to it is not verified value.
- An unattested value is reported under an explicit `unattested_*` field with the reason, never dropped to a silent zero and never reported as the old number.

## ARV ladder

    PRE-ARV0  no positive verified external value
    ARV0      >= 1 positive verified external-value event
    ARV1      >= 10 mUSD/day over a complete 30-day window
    ARV2      >= 100 mUSD/day over a complete 30-day window
    ARV3      >= 500 mUSD/day over a complete 30-day window
    ARV4      >= 2000 mUSD/day over a complete 30-day window

A level is reported only for value the view could attest. Offline, the ladder
cannot be climbed at all: the receipts re-derive, they are counted as claims, and
the level stays at its floor with the reason in `attestation_note`.

## Verified read side (trust modes)

    mycelium-economy --home ~/.mycelium/economy arv-status
    mycelium-economy --home ~/.mycelium/economy rv-status
    mycelium-economy --home ~/.mycelium/economy reinvestment-decision SIGNALS POLICY

Every one of these now carries `trust_mode` and an `attestation_note`, and
`economy-dashboard` carries a `trust` object with the endpoint, whether its
identity was enforced by the kernel, and the authority identity itself.

    trust_mode = "unverified"
        Offline only: hash chain, receipt re-validation, boundary derivation. No
        chain read. `verified_external_events`, `external_paid_jobs`,
        `verified_nev_musd_micros` and `available_new_commitment_musd_micros`
        are all 0 because nothing here is attested, and what the ledger claims
        appears in `unattested_*` together with the per-receipt reason.

    trust_mode = "provider_pinned"
        Additionally re-reads every cited transaction, block and ERC-20 log
        through a provider pinned out-of-band. A unix socket whose owner the
        kernel can verify is required; a loopback TCP port and the dev-only
        `MYCELIUM_DEV_BASE_PROVIDER` override are addresses, not identities, and
        are refused.

To reach an attested number, pin the provider first:

    mycelium-economy --home ~/.mycelium/economy \
      payment-policy-pin-provider unix:///run/mycelium-verifier.sock

The JSON output of `arv-status`, `rv-status`, `autonomy-status`, `revenue`,
`economy-dashboard`, `reinvestment-decision` and `reinvestment-decision-mupp`
gained `trust_mode` and the `unattested_*` fields described above. `autonomy-audit`
gained `stored_proof_verified_claims`, which counts the old claims for
diagnostics and is explicitly not an authority input. No field was removed.

## S1 shadow import

The S1 adapter accepts only Base chainId 8453 reports with measured=true, broadcast=false and profitIsReal=false. Each candidate becomes a Simulation OpportunityCandidate. Negative modeled beneficiary profit maps to zero expected value while retaining the signed S1 result in metadata, causing the Economic Orchestrator to reject it after Mycelium job cost.

Native PERCEPTION_SHADOW reports are also supported directly. A completed read-only report with no candidates is valid negative evidence and imports zero opportunities. A perception candidate is eligible only when its own report contains positive robust-net evidence; it remains requires_exact_sim=true and profit_is_real=false.

Example:

    mycelium-economy --home ~/.mycelium/economy agent-register-json config/economy/s1-agent.json

    mycelium-economy --home ~/.mycelium/economy s1-import-opportunities \
      /path/to/s1-edge-report.json s1-finance 0.05 120

    mycelium-economy --home ~/.mycelium/economy orchestrate OPPORTUNITY_ID 0.01

Accepted opportunities materialize a deterministic internal JobRequest once. Repeating orchestration is idempotent.

## Realized S1 outcome

The S1 outcome policy is intentionally separate from the Rabby payment policy. It binds the Mycelium verifier to the deployed S1 executor.

Do not configure this with a placeholder on the production ledger. Configure it only after the real executor is deployed and independently verified.

    mycelium-economy --home ~/.mycelium/economy \
      s1-outcome-policy-init 0xDEPLOYED_S1_EXECUTOR 2

After S1 emits its canonical sovereign_reconcile receipt:

    mycelium-economy --home ~/.mycelium/economy \
      s1-reconcile-outcome /path/to/reconcile-receipt.json \
      s1-finance OPPORTUNITY_ID http://127.0.0.1:8546

Only then can a verified ExternalValueReceipt be booked.

The reconciler cites the Base transaction hash as the receipt's `proof_hash` and
records the boundary evidence for the leg that actually moved USDC (executor to
beneficiary), so the value can be re-derived on read instead of merely claimed.
The S1 receipt hash stays in the ledger through `source_id`, so it remains
citable:

    source_id = s1-base:<base tx hash>:<s1 receipt hash>

Consequence, stated plainly: this changes the value written into **new** records,
so their `record_hash` differs from what an earlier build would have written.
Nothing already on disk is rewritten. An S1 receipt booked before this change
still deserializes and is still reported, as unattested, with the reason stated.

## Status commands

    mycelium-economy --home ~/.mycelium/economy agent-list
    mycelium-economy --home ~/.mycelium/economy autonomy-status
    mycelium-economy --home ~/.mycelium/economy autonomy-audit
    mycelium-economy --home ~/.mycelium/economy arv-status
    mycelium-economy --home ~/.mycelium/economy revenue
    mycelium-economy --home ~/.mycelium/economy audit-ledger

## Implementation phases

    A0  economic ABI                         IMPLEMENTED
    A1  EconomicAgent identity              IMPLEMENTED
    A2  OpportunityCandidate                IMPLEMENTED
    A3  deterministic Economic Orchestrator IMPLEMENTED
    A4  JobIntent + materialized JobRequest IMPLEMENTED
    A5  WorkReceipt/artifact verification   IMPLEMENTED
    A6  ExternalValueReceipt/provenance      IMPLEMENTED
    A7  anti-circular accounting + ARV       IMPLEMENTED
    A8  S1 read-only opportunity adapter     IMPLEMENTED
    A9  S1 realized-outcome verifier         IMPLEMENTED, awaits real executor/outcome
    A10 first real ARV0                      PENDING REAL EXTERNAL VALUE
    A11 TERR passive research adapter        IMPLEMENTED
    A12 adaptive NEV reinvestment            IMPLEMENTED
    A13 economic dashboard                   IMPLEMENTED
    A14 demand-driven scale controller       IMPLEMENTED (decision-only)
    A15 verified read side (P3)              IMPLEMENTED

## TERR passive research

TERR imports only causal runtime evidence. A direct snapshot must declare schema_version=2, kind=TERR_CAUSAL_SNAPSHOT, causal_only=true and lookahead_used=false. An S1 TERR context must be READY, passive_only=true and influences_execution=false.

A TERR Research Agent can request only validation, backtest or data_transform jobs. These jobs are internal_work=true, never authorize capital, and never book ExternalValue.

The current live TERR feed is still in warmup: 1 sample is present and the engine requires 513 before a READY causal snapshot can exist.

## Adaptive reinvestment

The controller computes automatic spending from verified net external value only. Verified losses reduce the base. The default policy keeps 10 mUSD outside automatic reinvestment, targets 20% of investable NEV, caps new daily commitments at 100 mUSD, and stops automatic commitments below 20% thermal headroom.

Risk, demand and thermal signals are brakes; none can increase the rate above the configured base rate.

The investment base is the view's verified NEV, so `reinvestment-commit` — the
one command that turns a number into real spending authority — is refused unless
a provider is pinned and the transaction behind the receipts is re-confirmed.
Offline, the refusal says so in terms rather than reporting a budget of zero.

## Dashboard

    mycelium-economy --home ~/.mycelium/economy economy-dashboard

This returns RV/PaidDemand, autonomous NEV/ARV, TERR research status, reinvestment commitments and the hard anti-circularity invariants in one JSON object.

## Demand-driven scale controller

Capacity is expressed in EconomicEquivalents, not machine count. The controller consumes measured paid work, utilization, queue pressure, p95 latency, revenue per equivalent, thermal headroom and current capacity.

It is decision-only: automatic_provisioning=false is hard-coded. Zero measured paid work can never trigger scale-out. High utilization alone is also insufficient; queue/latency pressure and minimum revenue per equivalent must support expansion.

    mycelium-economy --home ~/.mycelium/economy \
      scale-decision config/economy/scale-telemetry.json \
      config/economy/scale-policy.json

## MUPP physical gate

The S1-MUPP adapter is monotonic: it can only reduce thermal headroom supplied to reinvestment/scaling. It does not infer demand, profit, worker economics or financial risk from CPU/GPU utilization.

A stale MUPP state, invalid/unwarmed sensors, closed allow_execution gate, COLLAPSE or COOLDOWN force thermal_headroom=0. The default adapter freshness limit is 5 seconds. H >= 20 C maps to normalized thermal_headroom=1, but the original MUPP hard gates remain authoritative.

    mycelium-economy --home ~/.mycelium/economy \
      mupp-gate /tmp/s1-mupp-state.json

    mycelium-economy --home ~/.mycelium/economy \
      reinvestment-decision-mupp SIGNALS_JSON /tmp/s1-mupp-state.json

    mycelium-economy --home ~/.mycelium/economy \
      scale-decision-mupp TELEMETRY_JSON /tmp/s1-mupp-state.json

## Revenue definition

The system must preserve:

    InternalVolume != Revenue
    MYCEmission != Revenue
    BotServiceSpend != Revenue
    NoExternalProof => NoExternalValue
    TrustedNEV != receipt.proof_verified

For the current S1 path, NetExternalValue is conservatively the exact realized USDC beneficiary payout proven by the canonical Base transaction. MYC remains separate upside.
