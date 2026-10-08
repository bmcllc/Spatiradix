# Plan: Flash Loan Arbitrage Adapter for ARV0 Gate Crossing

## Objective
Build a **read-only** flash loan arbitrage scanning adapter that integrates with the existing P6 discovery machine, finds profitable opportunities on Base L2 using Balancer 0% fee flash loans, and feeds them through the existing S1 outcome verification path to generate the first ~$0.01 of external USDC needed to cross ARV0.

## Architecture Context (Confirmed)

### Current Flow
1. `S1ShadowEvidenceAdapter` (in `discovery.rs`) reads JSON files produced by an **external** S1 scanner
2. The S1 scanner runs independently, produces JSON shadow scan reports
3. `s1_outcome.rs` verifies realized outcomes by:
   - Checking the S1 executor address on Base
   - Reading the transaction receipt via pinned Unix-socket RPC
   - Matching SharedExecution events and USDC transfer logs
   - Producing `ExternalValueReceipt` → `VerifiedNev` → ARV0 crossing

### Key Constraints
- **Read-only**: `base_usdc.rs` verifier has NO broadcast capability (`eth_sendRawTransaction` is in the reject list)
- **External execution**: The adapter must NOT execute transactions — it can only observe and model
- **Trust model**: All chain reads go through pinned Unix-socket provider at `/run/mycelium-verifier.sock`
- **Zero capital**: Must use flash loans (no upfront USDC) — only minimal ETH for gas (~$0.01)

## Implementation Plan

### Phase 1: Flash Loan Arbitrage Scanner (Read-Only Observation)

**New file**: `crates/mycelium-economy/src/flash_arb_adapter.rs`

This adapter implements `OpportunityAdapter` for `OpportunityClass::Arbitrage`, replacing the S1 shadow file reader with a direct on-chain scanner that:

1. Queries Balancer Vault contract for flash loan availability (0% fee)
2. Scans DEX pools (Aerodrome, Uniswap V3, BaseSwap) for price discrepancies
3. Models arbitrage profit: `spread × loan_amount - gas_cost - loan_fee`
4. Produces `OpportunityCandidate` entries with metadata describing the route

**Key contract addresses on Base (chain 8453)**:
- Balancer Vault: `0xBA12222222228d8Ba445958a71eAFfee3787EC92`
- Balancer FlashLoan simple type: 0% fee
- Aerodrome Router: `0xcF77a3Ba9A5CA389B7c97C74d54e5b1Beb874E43`
- Uniswap V3 Router: `0x2626664c2603336E57B271c5C0b26F421741e481`
- USDC: `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`

**Read-only RPC methods needed** (must add to `base_usdc.rs` allowlist):
- `eth_call` — to query pool reserves/prices (currently NOT in allowlist)
- `eth_getCode` — verify contract bytecode exists (already allowed)

### Phase 2: Extend Base Usdc Verifier for eth_call

**Modify**: `crates/mycelium-economy/src/base_usdc.rs`

Add `eth_call` to the RPC allowlist, but only for **read-only contract view functions**. This is safe because:
- `eth_call` simulates execution without broadcasting
- The verifier already validates chain ID, block hash, and provider identity
- No state-changing operations can be performed via `eth_call`

### Phase 3: Output Format Compatible with S1 Outcome Verification

The adapter produces `OpportunityCandidate` entries that, when a real flash loan executes via an external S1 executor, create `ExternalValueReceipt` records that `s1_outcome.rs` can verify.

The key insight: the adapter itself only **models** opportunities; the actual flash loan execution happens externally (via the S1 executor with its own gas/ETH). When a profitable opportunity is found, the S1 executor:
1. Borrows USDC via Balancer flash loan (0% fee)
2. Executes arbitrage across DEXes  
3. Repays the flash loan + any fee
4. Sends beneficiary profit USDC to the controlled wallet
5. The beneficiary transfer is verified by `s1_outcome.rs`

### Phase 4: Integration into AdapterRegistry

Register the new adapter in `crate::discovery::AdapterRegistry::crate_default()` alongside or replacing the S1 shadow evidence adapter.

### Phase 5: Validation

- Unit tests for the flash loan scanner (mocked RPC responses)
- Integration test with the existing `s1_outcome.rs` verification path
- Run 4X simulation to confirm the economic invariants still hold

## File Changes

| File | Action |
|------|--------|
| `crates/mycelium-economy/src/flash_arb_adapter.rs` | **New** — read-only flash loan arbitrage scanner |
| `crates/mycelium-economy/src/base_usdc.rs` | Add `eth_call` to RPC allowlist with read-only safeguards |
| `crates/mycelium-economy/src/discovery.rs` | Register new adapter in `AdapterRegistry::crate_default` |
| `crates/mycelium-economy/src/lib.rs` | Add `pub mod flash_arb_adapter;` |
| `crates/mycelium-economy/tests/flash_arb_tests.rs` | New test file |

## Risk Mitigation

1. **Gas requirement**: The adapter only models opportunities — actual gas/ETH for execution comes from the S1 executor's own funds
2. **Flash loan availability**: Balancer 0% fee flash loans are well-established on Base
3. **Price oracle manipulation**: The adapter will only flag opportunities with spreads > 2x estimated gas cost as a safety margin
4. **MEV sandwich attacks**: Model conservatively with slippage assumptions built in

## Success Criteria

1. Adapter scans Base L2 DEX pools and identifies arbitrage opportunities
2. Opportunities are priced with gas costs and safety margins
3. Valid opportunities produce `OpportunityCandidate` entries that pass through `orchestrate()`
4. When executed externally, the USDC transfer to the controlled beneficiary is verifiable by `s1_outcome.rs`
5. This generates the first external USDC value → ARV0 gate crossing → starts autonomous revenue loop