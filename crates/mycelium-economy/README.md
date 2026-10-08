# Mycelium Economy — RV0

Local-first Revenue Validation core for Mycelium.

## RV ladder

- RV0: at least one externally paid, verified and settled job.
- RV1: >= 10 mUSD/day average over a complete 30-day window.
- RV2: >= 100 mUSD/day average over a complete 30-day window.
- RV3: >= 500 mUSD/day average over a complete 30-day window.
- RV4: >= 2000 mUSD/day average over a complete 30-day window.

Simulated work, internal work and MYC rewards never count as PaidDemand.

## Hard accounting invariants

1. internal_work=true never increases PaidDemand.
2. simulated settlement never increases PaidDemand.
3. external settlement requires verified work.
4. external settlement requires a verified payment proof.
5. Base/USDC payment must match the job price exactly.
6. a Base payment must be in a block strictly after the recorded PaymentIntent anchor.
7. a payment transaction hash cannot be reused.
8. RV1-RV4 require a complete 30-day paid-demand window.
9. ledger records are BLAKE3 hash-chained and all reads fail closed on tampering.
10. the Base adapter is read-only, and only talks to a provider that was pinned out-of-band.
11. an unpinned chain provider is refused; there is no default endpoint to fall back to.
12. a stored `proof_verified` / `payment_proof_verified` / `external_paid` boolean is a claim, not an authority input; no economic path reads it.
13. every economic number is re-derived on read by `verified_view`; the only actionable number is a `VerifiedNev`, which no other code can construct.
14. `TrustMode::Unverified` (offline) can never promote a level and can never fund a commitment.

## Verified read side

    TrustedNEV = VerifyChain(VerifyPolicy(DeriveBoundary(Evidence)))

Every economic number comes out of `verified_view::VerifiedEconomyView` (autonomy
ledger: ARV, verified NEV, reinvestment) or `verified_view::VerifiedRevenueView`
(revenue ledger: RV, paid demand), and is derived in this order:

1. the hash chain, re-validated on read;
2. the record's own validation rules, re-run on read, including `gross - cost`;
3. the boundary, re-derived from stored `BoundaryEvidence` against a
   `ControlledAddressRegistry` the operator controls;
4. the cited transaction, block and ERC-20 log, re-read from a pinned provider.

The view reports its mode, and the mode is a property of the number, not of the
label:

| `trust_mode` | what it ran | can promote | can fund |
| --- | --- | --- | --- |
| `unverified` | 1-3, no chain read | no | no |
| `provider_pinned` | 1-4 | yes | yes |

`Unverified` is refused by construction, not by a runtime check:
`VerifiedNev` has private fields, no `Deserialize` and no public constructor, and
the offline path returns a different type, `UnattestedNev`, which no promotion
predicate or budget gate accepts. A provider whose identity the kernel does not
enforce — a loopback TCP port, or the dev-only `MYCELIUM_DEV_BASE_PROVIDER`
override — cannot produce a `VerifiedNev` at all, because
`VerifiedEconomyView::provider_pinned` refuses to construct.

What the ledger claims is still reported, under names that cannot be mistaken for
an attested total: `unattested_external_events`,
`unattested_net_external_value_musd`, `unattested_external_paid_jobs`,
`unattested_paid_demand_musd_total`, `unattested_nev_musd_micros`, plus
`attestation_note` naming the reason per receipt. Nothing is dropped to a silent
zero and nothing is reported as the old number.

## Local Base adapter

Current Base USDC:

0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913

The verifier implements only:

- eth_chainId
- eth_blockNumber
- eth_getCode
- eth_getBlockByNumber
- eth_getTransactionReceipt
- eth_getTransactionByHash

There is no signing or transaction-broadcast method.

## Chain provider pinning

The endpoint is NOT a command-line argument. "It is on localhost" is not an
identity: any process that can bind a free loopback port can serve synthetic
chain answers and mint a genuine-looking receipt through the legitimate path.

The endpoint therefore comes from, in this order:

1. `MYCELIUM_DEV_BASE_PROVIDER` — development/test only. The only way to select
   a loopback HTTP endpoint, and unauthenticated by construction: every
   verification it produces is reported with
   `provider_identity_verified: false`.
2. The provider pinned in `payment-policy.json` (`chain_provider`). A policy
   pin must be a Unix domain socket, whose inode ownership and permission bits
   the kernel enforces on `connect(2)`. The socket must not be group- or
   other-writable and must be owned by the pinned UID (uid 0 when the pin names
   none).
3. Nothing. No pin means the verifier refuses.

Pin one:

    target/debug/mycelium-economy --home ~/.mycelium/economy payment-policy-pin-provider unix:///run/mycelium-verifier.sock

or pin it when creating the policy:

    target/debug/mycelium-economy --home ~/.mycelium/economy payment-policy-init 0xYOUR_PUBLIC_BASE_ADDRESS 2 unix:///run/mycelium-verifier.sock

The pinned socket must exist by the time a chain command runs, otherwise the
verifier fails closed naming the path.

What this does not defend against: root or full host compromise; an attacker
running as the same OS principal who can replace the binary, read the socket or
write the policy file; a compromised upstream Base node. No key in the same
`$HOME` changes that.

## Build/test

    cd crates/mycelium-economy
    cargo test
    cargo build --bin mycelium-economy

## Bootstrap payment policy

Use only a public Base address you control. Never put a private key, seed phrase or password here.

    target/debug/mycelium-economy --home ~/.mycelium/economy payment-policy-init 0xYOUR_PUBLIC_BASE_ADDRESS 2

The policy is create-once for this RV0 ledger.

## Create an external job

    target/debug/mycelium-economy --home ~/.mycelium/economy job-create build customer-id blake3:INPUT_HASH 7.50 false "build description"

## Verify a produced artifact

    target/debug/mycelium-economy --home ~/.mycelium/economy work-verify-file JOB_ID worker-id /absolute/path/to/artifact verifier-id

The receipt stores a BLAKE3 result hash and file size. It does not execute arbitrary customer shell commands.

## Create payment instructions

This step reads the current Base block through the pinned provider and records a PaymentIntent.

    target/debug/mycelium-economy --home ~/.mycelium/economy payment-instructions JOB_ID

The customer must transfer exactly the shown USDC amount to the shown recipient in a later Base block.

## Diagnostic verification only

This checks an existing transfer but does not touch the Revenue Ledger:

    target/debug/mycelium-economy --home ~/.mycelium/economy verify-base-usdc TX_HASH RECIPIENT AMOUNT_USDC

## Final settlement

After the work is verified and the customer payment is confirmed:

    target/debug/mycelium-economy --home ~/.mycelium/economy settle-base-usdc JOB_ID TX_HASH

This is a read-only chain verification followed by a local ledger append. The verifier itself cannot broadcast transactions.

## Audit and RV status

    target/debug/mycelium-economy --home ~/.mycelium/economy audit-ledger
    target/debug/mycelium-economy --home ~/.mycelium/economy revenue
    target/debug/mycelium-economy --home ~/.mycelium/economy rv-status

RV0 is not reached until one external payment is verified for a real external job.

`rv-status` and `revenue` report `trust_mode`. Without a pinned provider they run
in `TrustMode::unverified` and `external_paid_jobs` is 0 with the reason in
`attestation_note`: a settlement that cites no re-confirmable transaction cannot
be paid demand.
