//! Read-only flash loan arbitrage scanner for Base L2.
//!
//! This adapter implements [`OpportunityAdapter`](crate::discovery::OpportunityAdapter)
//! for [`OpportunityClass::Arbitrage`](crate::discovery::OpportunityClass::Arbitrage).
//! It scans Base L2 DEX pools for price discrepancies that could be exploited via
//! a Balancer 0%-fee flash loan, and emits [`OpportunityCandidate`] entries for the
//! P6 discovery machine to classify.
//!
//! # Zero-capital design
//!
//! The adapter itself never executes. It only reads on-chain DEX pricing data
//! via `eth_call` (read-only contract view functions) and models the expected
//! profit from a flash loan arbitrage. The actual flash loan execution happens
//! externally — the S1 executor with its own ETH for gas broadcasts the
//! transaction, then verifies the outcome through [`crate::s1_outcome`].
//!
//! # Contract addresses on Base (chain ID 8453)
//!
//! Every address below was checked with `eth_getCode` on Base mainnet and the
//! quoters were exercised with real `eth_call`s; Balancer's come from
//! `balancer-deployments/addresses/base.json`. The flash loan fee is not a
//! constant: it is governance-set and is read from the ProtocolFeesCollector on
//! every scan.
//!
//! - Balancer V2 Vault (flash loan source): [`BALANCER_VAULT`]
//! - Balancer ProtocolFeesCollector (flash loan fee): [`BALANCER_FEES_COLLECTOR`]
//! - Aerodrome Router (quote + execution): [`AERODROME_ROUTER`]
//! - Uniswap V3 QuoterV2 (quote): [`UNISWAP_V3_QUOTER`]
//! - Uniswap V3 SwapRouter02 (execution): [`UNISWAP_V3_ROUTER`]
//! - USDC (settlement token): `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`

use crate::{
    autonomy::OpportunityCandidate,
    base_usdc::{BaseUsdcVerifier, BASE_CHAIN_ID, BASE_USDC},
    chain_provider::{resolve, PinnedChainProvider},
    discovery::{
        BudgetSpend, MeasuredEdge, OpportunityAdapter, OpportunityClass, SearchPermit,
        SearchObservation, SettlementReadiness, ValuationReadiness, ObservedThermal,
    },
    stable_id, EconomyError, JobType, Result, SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// Balancer V2 Vault on Base — the flash loan source.
pub const BALANCER_VAULT: &str = "0xba12222222228d8ba445958a75a0704d566bf2c8";

/// Balancer ProtocolFeesCollector on Base (immutable in the Vault). Its
/// `getFlashLoanFeePercentage()` is the flash loan fee, 1e18 = 100%.
pub const BALANCER_FEES_COLLECTOR: &str = "0xce88686553686da562ce7cea497ce749da109f9f";

/// Aerodrome Router on Base.
pub const AERODROME_ROUTER: &str = "0xcf77a3ba9a5ca399b7c97c74d54e5b1beb874e43";

/// Aerodrome volatile/stable pool factory, named in every `getAmountsOut` route.
pub const AERODROME_FACTORY: &str = "0x420dd381b31aef6683db6b902084cb0ffece40da";

/// Uniswap V3 SwapRouter02 on Base (execution venue; it cannot quote).
pub const UNISWAP_V3_ROUTER: &str = "0x2626664c2603336e57b271c5c0b26f421741e481";

/// Uniswap V3 QuoterV2 on Base — the contract that actually answers quotes.
pub const UNISWAP_V3_QUOTER: &str = "0x3d4e44eb1374240ce5f1b871ab261cd16335b76a";

/// Uniswap V3 fee tier quoted for WETH/USDC (0.05%, the deepest pool).
const UNISWAP_FEE_TIER: u64 = 500;

/// Estimated gas cost in USDC for a flash loan arbitrage transaction on Base.
/// Based on ~$0.001-0.005 per transaction * ~800K gas * ~$0.0000001/gas.
pub const ESTIMATED_GAS_COST_USDC_MICROS: i64 = 500; // $0.0005

/// Minimum safety margin in USDC micros to require above gas + fee costs.
/// Ensures we only flag opportunities with genuine profit.
pub const SAFETY_MARGIN_USDC_MICROS: u64 = 1_000_000; // $1.00

/// A DEX pool pair with price information.
#[derive(Debug, Clone)]
pub struct DexPrice {
    pub dex_name: String,
    pub token_in: String,
    pub token_out: String,
    pub amount_in: u64,
    pub amount_out: u64,
    /// Computed price: amount_out / amount_in (in USDC micros per USDC micro)
    pub price: f64,
}

/// A modeled flash loan arbitrage opportunity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlashArbOpportunity {
    /// Which DEXes are involved in the arbitrage loop.
    pub dex_pair: String,
    /// The direction of the arbitrage (tokenA -> DEX1 -> tokenB -> DEX2 -> tokenA).
    pub route: Vec<String>,
    /// Modeled profit after gas and fees, in USDC micros.
    pub modeled_profit_usdc_micros: i64,
    /// Gross profit before costs, in USDC micros.
    pub gross_profit_usdc_micros: u64,
    /// Estimated network cost (gas + loan fee) in USDC micros.
    pub network_cost_usdc_micros: u64,
    /// The flash loan amount in USDC micros.
    pub flash_loan_amount_usdc_micros: u64,
    /// Safety margin applied.
    pub safety_margin_usdc_micros: u64,
}

/// Configuration for the flash loan arbitrage adapter.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlashArbConfig {
    /// Agent identity for the audit trail.
    pub agent_id: String,
    /// Minimum modeled profit required to flag an opportunity (in mUSD micros).
    pub min_profit_musd_micros: u64,
    /// TTL for opportunity entries in seconds.
    pub ttl_seconds: u64,
    /// Flash loan amount to model (in USDC micros, i.e. $1 USDC = 1_000_000).
    pub loan_amount_usdc_micros: u64,
    /// Which DEX pairs to scan. Defaults to all known.
    pub dex_pairs: Vec<DexPair>,
}

impl Default for FlashArbConfig {
    fn default() -> Self {
        Self {
            agent_id: "flash-arb-scanner".into(),
            min_profit_musd_micros: 10_000,
            ttl_seconds: 120,
            loan_amount_usdc_micros: 100_000_000, // $100 USDC
            dex_pairs: vec![
                DexPair::AerodromeToUniswap,
                DexPair::UniswapToAerodrome,
            ],
        }
    }
}

/// DEX pair combinations to scan for arbitrage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DexPair {
    AerodromeToUniswap,
    UniswapToAerodrome,
}

/// The flash loan arbitrage adapter.
///
/// This adapter is read-only: it queries DEX pool reserves and spot prices
/// through the pinned Base read-only verifier, models arbitrage opportunities,
/// and emits [`OpportunityCandidate`] entries. It never broadcasts transactions.
#[derive(Debug, Clone)]
pub struct FlashArbAdapter {
    config: FlashArbConfig,
    /// The pinned verifier used for all chain reads. This comes from the
    /// same policy pin that secures every other chain read in this crate.
    verifier: BaseUsdcVerifier,
}

impl FlashArbAdapter {
    pub fn new(config: FlashArbConfig, verifier: BaseUsdcVerifier) -> Result<Self> {
        if config.agent_id.trim().is_empty() {
            return Err(EconomyError::Invalid(
                "flash arb adapter requires a non-empty agent_id".into(),
            ));
        }
        if config.min_profit_musd_micros == 0 {
            return Err(EconomyError::Invalid(
                "min_profit_musd_micros must be > 0".into(),
            ));
        }
        if config.ttl_seconds == 0 {
            return Err(EconomyError::Invalid(
                "ttl_seconds must be > 0".into(),
            ));
        }
        if config.loan_amount_usdc_micros == 0 || config.loan_amount_usdc_micros > i64::MAX as u64 {
            return Err(EconomyError::Invalid(
                "loan_amount_usdc_micros must be in 1..=i64::MAX".into(),
            ));
        }
        Ok(Self { config, verifier })
    }

    /// Query a DEX for the output amount of a swap, through the contract that
    /// really quotes (Aerodrome Router, Uniswap QuoterV2). Read-only `eth_call`.
    fn query_dex_price(
        &self,
        router_address: &str,
        token_in: &str,
        token_out: &str,
        amount_in: u64,
    ) -> Result<u64> {
        let payload = self.build_price_query(router_address, token_in, token_out, amount_in)?;
        let result = self.verifier.rpc_call("eth_call", payload)?;
        Self::decode_amount_out(router_address, &result)
    }

    /// Build the eth_call payload for querying a DEX's spot price.
    // shortcut: "latest" per call, so the two legs of a scan may straddle a block; pin
    // one block number across the scan when that shows up in the shadow data.
    fn build_price_query(
        &self,
        router_address: &str,
        token_in: &str,
        token_out: &str,
        amount_in: u64,
    ) -> Result<Value> {
        let to = if router_address.eq_ignore_ascii_case(AERODROME_ROUTER) {
            AERODROME_ROUTER
        } else if router_address.eq_ignore_ascii_case(UNISWAP_V3_ROUTER) {
            UNISWAP_V3_QUOTER // the SwapRouter cannot quote
        } else {
            return Err(EconomyError::Invalid(format!("no quoter known for {router_address}")));
        };
        let data = self.build_dex_calldata(router_address, token_in, token_out, amount_in)?;
        Ok(json!([{ "to": to, "data": data }, "latest"]))
    }

    /// Build the calldata for each DEX's quote function. Selectors are
    /// keccak256 of the signatures below, and were checked against Base.
    fn build_dex_calldata(
        &self,
        router_address: &str,
        token_in: &str,
        token_out: &str,
        amount_in: u64,
    ) -> Result<String> {
        let (tin, tout) = (addr_word(token_in)?, addr_word(token_out)?);
        if router_address.eq_ignore_ascii_case(AERODROME_ROUTER) {
            // getAmountsOut(uint256,(address from,address to,bool stable,address factory)[])
            // with one volatile route: head = amountIn, offset 0x40; array = len 1, tuple.
            Ok(format!(
                "0x5509a1ac{amount_in:064x}{:064x}{:064x}{tin}{tout}{:064x}{}",
                64,
                1,
                0,
                addr_word(AERODROME_FACTORY)?
            ))
        } else if router_address.eq_ignore_ascii_case(UNISWAP_V3_ROUTER) {
            // QuoterV2.quoteExactInputSingle((tokenIn,tokenOut,amountIn,fee,sqrtPriceLimitX96))
            Ok(format!(
                "0xc6a5026a{tin}{tout}{amount_in:064x}{:064x}{:064x}",
                UNISWAP_FEE_TIER, 0
            ))
        } else {
            Err(EconomyError::Invalid(format!("no quoter known for {router_address}")))
        }
    }

    /// QuoterV2 returns `amountOut` as its first word; the Aerodrome Router returns a
    /// `uint256[]` (offset, length, amounts…) whose last element is `amountOut`.
    ///
    /// An empty result is an `eth_call` to an address with no code, not a zero
    /// quote, so it is an error rather than `0`.
    fn decode_amount_out(router_address: &str, result: &Value) -> Result<u64> {
        let hex = result.as_str().and_then(|s| s.strip_prefix("0x")).unwrap_or("");
        let words: Vec<&str> = (0..hex.len() / 64).map(|i| &hex[i * 64..(i + 1) * 64]).collect();
        let bad = |why: &str| EconomyError::Invalid(format!("eth_call quote from {router_address}: {why}"));
        if hex.is_empty() || hex.len() % 64 != 0 || !hex.is_ascii() {
            return Err(bad("empty or malformed result (no contract at that address?)"));
        }
        let word = if router_address.eq_ignore_ascii_case(AERODROME_ROUTER) {
            if words.len() < 4 || word_u64(words[1]).ok() != Some(words.len() as u64 - 2) {
                return Err(bad("not a uint256[] of at least two amounts"));
            }
            words[words.len() - 1]
        } else {
            words[0]
        };
        word_u64(word).map_err(|_| bad("amount is not a u64"))
    }

    /// Check the Balancer Vault exists on Base and that we are on Base.
    fn verify_flash_loan_available(&self) -> Result<()> {
        // Check that the Balancer Vault contract has bytecode on Base.
        let code = self.verifier.rpc_call(
            "eth_getCode",
            json!([BALANCER_VAULT, "latest"]),
        )?;

        let code_str = code.as_str().unwrap_or_default();
        if code_str == "0x" || code_str == "0x0" {
            return Err(EconomyError::Invalid(
                "Balancer Vault has no bytecode on Base L2".into(),
            ));
        }

        // Verify chain ID is Base.
        let chain_id = self.verifier.rpc_call("eth_chainId", json!([]))?;
        let chain_id_str = chain_id.as_str().unwrap_or("0x0");
        let chain_id_val = u64::from_str_radix(
            chain_id_str.strip_prefix("0x").unwrap_or(chain_id_str),
            16,
        )
        .map_err(|_| EconomyError::Invalid("invalid chain ID format".into()))?;

        if chain_id_val != BASE_CHAIN_ID {
            return Err(EconomyError::Invalid(format!(
                "expected Base chain ID {}, got {}",
                BASE_CHAIN_ID, chain_id_val
            )));
        }

        Ok(())
    }

    /// Balancer's flash loan fee in bps, rounded up, read live because it is
    /// governance-set. `getFlashLoanFeePercentage()` is 1e18 = 100%, so 1 bp = 1e14.
    fn flash_loan_fee_bps(&self) -> Result<u64> {
        let r = self.verifier.rpc_call(
            "eth_call",
            json!([{ "to": BALANCER_FEES_COLLECTOR, "data": "0xd877845c" }, "latest"]),
        )?;
        let hex = r.as_str().and_then(|s| s.strip_prefix("0x")).unwrap_or("");
        let pct = (hex.len() == 64)
            .then(|| u128::from_str_radix(hex, 16).ok())
            .flatten()
            .filter(|p| *p <= 10u128.pow(18))
            .ok_or_else(|| EconomyError::Invalid("unreadable Balancer flash loan fee".into()))?;
        Ok(pct.div_ceil(10u128.pow(14)) as u64)
    }

    /// Scan a single DEX pair. Always returns the signed edge actually measured;
    /// the opportunity is `Some` only when it clears the safety margin.
    fn scan_pair(
        &self,
        pair: DexPair,
        fee_bps: u64,
    ) -> Result<(MeasuredEdge, Option<FlashArbOpportunity>)> {
        let (dex_a, dex_b) = match pair {
            DexPair::AerodromeToUniswap => (AERODROME_ROUTER, UNISWAP_V3_ROUTER),
            DexPair::UniswapToAerodrome => (UNISWAP_V3_ROUTER, AERODROME_ROUTER),
        };

        let loan_amount = self.config.loan_amount_usdc_micros;

        // USDC -> WETH on DEX A, WETH -> USDC on DEX B.
        let weth: &str = "0x4200000000000000000000000000000000000006";
        let amount_out_a = self.query_dex_price(dex_a, BASE_USDC, weth, loan_amount)?;
        // A zero quote is "no liquidity", not a measurement of zero edge.
        if amount_out_a == 0 {
            return Err(EconomyError::Invalid(format!("{} quoted 0 WETH", pair_as_str(pair))));
        }
        let amount_back_b = self.query_dex_price(dex_b, weth, BASE_USDC, amount_out_a)?;
        if amount_back_b == 0 {
            return Err(EconomyError::Invalid(format!("{} quoted 0 USDC back", pair_as_str(pair))));
        }

        let gross = i64::try_from(amount_back_b).unwrap_or(i64::MAX) - loan_amount as i64;
        let loan_fee = (loan_amount as u128 * fee_bps as u128).div_ceil(10_000) as i64;
        let network_cost = ESTIMATED_GAS_COST_USDC_MICROS.saturating_add(loan_fee);
        let modeled_profit = gross - network_cost;

        let edge = MeasuredEdge {
            token_edge_micros: Some(gross),
            robust_net_micros: modeled_profit,
            source_field: format!("flash_arb::{}", pair_as_str(pair)),
        };
        let opportunity = (gross > 0 && modeled_profit >= SAFETY_MARGIN_USDC_MICROS as i64).then(|| {
            FlashArbOpportunity {
                dex_pair: pair_as_str(pair).to_string(),
                route: vec!["USDC".to_string(), "WETH".to_string(), "USDC".to_string()],
                modeled_profit_usdc_micros: modeled_profit,
                gross_profit_usdc_micros: gross as u64,
                network_cost_usdc_micros: network_cost as u64,
                flash_loan_amount_usdc_micros: loan_amount,
                safety_margin_usdc_micros: SAFETY_MARGIN_USDC_MICROS,
            }
        });
        Ok((edge, opportunity))
    }

    /// Scan all configured DEX pairs; every pair contributes its measured edge.
    fn scan_all_pairs(&self) -> Result<(Vec<FlashArbOpportunity>, Vec<MeasuredEdge>)> {
        self.verify_flash_loan_available()?;
        let fee_bps = self.flash_loan_fee_bps()?;

        let mut opportunities = Vec::new();
        let mut measured_edges = Vec::new();
        for pair in &self.config.dex_pairs {
            // A failed quote is not a measurement: `?` fails the whole scan, which
            // `observe` reports as unmeasured, instead of booking it as "no edge".
            let (edge, opp) = self.scan_pair(*pair, fee_bps)?;
            measured_edges.push(edge);
            opportunities.extend(opp);
        }
        Ok((opportunities, measured_edges))
    }

    /// Convert a flash arbitrage opportunity into an OpportunityCandidate.
    fn to_opportunity_candidate(&self, opp: &FlashArbOpportunity, observed_at_unix: u64) -> OpportunityCandidate {
        let expires_at_unix = observed_at_unix.saturating_add(self.config.ttl_seconds);
        let profit_usd_micros = opp.modeled_profit_usdc_micros.max(0) as u64;

        let opportunity_id = stable_id(
            "flasharb",
            &[
                &self.config.agent_id,
                &opp.dex_pair,
                &opp.flash_loan_amount_usdc_micros.to_string(),
                &observed_at_unix.to_string(),
            ],
        );

        let evidence_hash = format!(
            "blake3:{}",
            blake3::hash(
                format!(
                    "{}:{}:{}:{}",
                    &opp.dex_pair,
                    opp.flash_loan_amount_usdc_micros,
                    observed_at_unix,
                    opp.modeled_profit_usdc_micros
                )
                .as_bytes()
            )
            .to_hex()
        );

        let mut metadata = BTreeMap::new();
        metadata.insert("source".into(), "flash_arb_scanner".into());
        metadata.insert("dex_pair".into(), opp.dex_pair.clone());
        metadata.insert(
            "modeled_profit_usdc_micros_raw".into(),
            opp.modeled_profit_usdc_micros.to_string(),
        );
        metadata.insert(
            "gross_profit_usdc_micros".into(),
            opp.gross_profit_usdc_micros.to_string(),
        );
        metadata.insert(
            "network_cost_usdc_micros".into(),
            opp.network_cost_usdc_micros.to_string(),
        );
        metadata.insert(
            "flash_loan_amount_usdc_micros".into(),
            opp.flash_loan_amount_usdc_micros.to_string(),
        );
        metadata.insert(
            "safety_margin_usdc_micros".into(),
            opp.safety_margin_usdc_micros.to_string(),
        );
        metadata.insert("chain_id".into(), BASE_CHAIN_ID.to_string());
        metadata.insert("dex_a".into(), match opp.dex_pair.split('→').next() {
            Some("Aerodrome") => AERODROME_ROUTER,
            Some("Uniswap") => UNISWAP_V3_ROUTER,
            _ => "unknown",
        }.to_string());

        OpportunityCandidate {
            schema_version: SCHEMA_VERSION,
            opportunity_id,
            agent_id: self.config.agent_id.clone(),
            observed_at_unix,
            expires_at_unix,
            job_type: JobType::Simulation,
            input_hash: evidence_hash.clone(),
            evidence_hash,
            expected_gross_musd_micros: profit_usd_micros,
            expected_external_cost_musd_micros: 0,
            estimated_job_cost_musd_micros: self.config.min_profit_musd_micros / 10,
            risk_buffer_musd_micros: SAFETY_MARGIN_USDC_MICROS * 1_000,
            metadata,
        }
    }
}

impl OpportunityAdapter for FlashArbAdapter {
    fn class(&self) -> OpportunityClass {
        OpportunityClass::Arbitrage
    }

    fn identity(&self) -> &str {
        "flash_arb_scanner_v1"
    }

    fn observe(&self, permit: &SearchPermit, now_unix: u64) -> Result<SearchObservation> {
        if permit.class != OpportunityClass::Arbitrage {
            return Err(EconomyError::Invalid(format!(
                "flash arb adapter received permit for class {} instead of Arbitrage",
                permit.class
            )));
        }

        match self.scan_all_pairs() {
            Ok((opportunities, measured_edges)) => {
                let candidates: Vec<OpportunityCandidate> = opportunities
                    .iter()
                    .map(|o| self.to_opportunity_candidate(o, now_unix))
                    .collect();

                let best_observed_edge = measured_edges.into_iter().max_by_key(|e| e.robust_net_micros);

                Ok(SearchObservation {
                    schema_version: SCHEMA_VERSION,
                    class: OpportunityClass::Arbitrage,
                    adapter: self.identity().to_string(),
                    cycle: permit.cycle,
                    cycles_budgeted: 1,
                    cycles_completed: 1,
                    cells_scanned: Some(opportunities.len() as u64 + 1),
                    aborted: false,
                    best_observed_edge,
                    candidates,
                    settlement: SettlementReadiness::NotApplicable,
                    valuation: ValuationReadiness::NotRequired,
                    thermal: ObservedThermal::default(),
                    spend: BudgetSpend::cycles(1),
                    resolution: None,
                    defect: None,
                })
            }
            Err(e) => {
                // If scanning fails entirely, report as defective evidence
                Ok(SearchObservation::defective(
                    OpportunityClass::Arbitrage,
                    self.identity(),
                    permit.cycle,
                    crate::discovery::EvidenceDefect::Unmeasured {
                        why: format!("flash arb scanner failed: {}", e),
                    },
                ))
            }
        }
    }
}

/// Helper: convert a DexPair to a human-readable string.
fn pair_as_str(pair: DexPair) -> &'static str {
    match pair {
        DexPair::AerodromeToUniswap => "Aerodrome→Uniswap",
        DexPair::UniswapToAerodrome => "Uniswap→Aerodrome",
    }
}

/// A 20-byte `0x` address as a 32-byte ABI word.
fn addr_word(addr: &str) -> Result<String> {
    match addr.strip_prefix("0x") {
        Some(h) if h.len() == 40 && h.bytes().all(|b| b.is_ascii_hexdigit()) => {
            Ok(format!("{:0>64}", h.to_ascii_lowercase()))
        }
        _ => Err(EconomyError::Invalid(format!("not a 20-byte 0x address: {addr}"))),
    }
}

/// A 32-byte ABI word as u64; errors if it does not fit.
fn word_u64(w: &str) -> Result<u64> {
    let t = w.trim_start_matches('0');
    if t.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(t, 16).map_err(|_| EconomyError::Invalid(format!("word does not fit u64: {w}")))
}

/// Create a flash arbitrage adapter from a pinned provider.
///
/// This is the primary entry point for constructing the adapter in production:
/// it takes a validated pinned provider and builds the read-only verifier
/// that secures all chain reads.
pub fn create_from_pinned_provider(
    config: FlashArbConfig,
    provider: &PinnedChainProvider,
) -> Result<FlashArbAdapter> {
    provider.validate_policy_pin()?;
    let resolved = resolve(None, Some(provider))?;
    let verifier = BaseUsdcVerifier::from_resolved(&resolved, config.min_confirmations())?;
    Ok(FlashArbAdapter::new(config, verifier)?)
}

impl FlashArbConfig {
    /// Returns the chain ID (always Base mainnet).
    pub fn chain_id(&self) -> u64 {
        BASE_CHAIN_ID
    }

    /// Returns the minimum confirmations required.
    pub fn min_confirmations(&self) -> u64 {
        2
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc_test_server::FakeRpcSocket;

    const WETH: &str = "0x4200000000000000000000000000000000000006";

    /// A fake Base: both venues quote WETH at a USD price, Balancer charges `fee_1e18`.
    #[derive(Clone, Copy)]
    struct Market {
        uni_usd: u128,
        aero_usd: u128,
        fee_1e18: u128,
        /// The Uniswap quoter address has no code, so `eth_call` returns "0x".
        dead_quoter: bool,
    }

    impl Market {
        fn flat() -> Self {
            Self { uni_usd: 3_000, aero_usd: 3_000, fee_1e18: 0, dead_quoter: false }
        }

        /// What the contract at `to` answers for `data`, shaped like the real return.
        fn eth_call(&self, to: &str, data: &str) -> String {
            let word = |s: &str, i: usize| u128::from_str_radix(&s[i * 64 + 32..(i + 1) * 64], 16).unwrap();
            let is_weth = |s: &str, i: usize| s[i * 64 + 24..(i + 1) * 64].eq_ignore_ascii_case(&WETH[2..]);
            let quote = |usd: u128, weth_in: bool, amt: u128| {
                if weth_in { amt * usd / 10u128.pow(12) } else { amt * 10u128.pow(12) / usd }
            };
            let body = &data[10..];
            if to == BALANCER_FEES_COLLECTOR && data == "0xd877845c" {
                format!("0x{:064x}", self.fee_1e18)
            } else if to == UNISWAP_V3_QUOTER && data.starts_with("0xc6a5026a") && !self.dead_quoter {
                let out = quote(self.uni_usd, is_weth(body, 0), word(body, 2));
                format!("0x{out:064x}{:064x}{:064x}{:064x}", 0, 0, 0)
            } else if to == AERODROME_ROUTER && data.starts_with("0x5509a1ac") {
                let amt = word(body, 0);
                let out = quote(self.aero_usd, is_weth(body, 3), amt);
                format!("0x{:064x}{:064x}{amt:064x}{out:064x}", 0x20, 2)
            } else {
                "0x".into() // an eth_call to an address with no code
            }
        }
    }

    /// An adapter reading `market` through the real pinned-socket path.
    fn adapter(market: Market) -> (FlashArbAdapter, FakeRpcSocket, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let socket = FakeRpcSocket::with_dispatch(dir.path().join("v.sock"), move |method, params| {
            Some(match method {
                "eth_chainId" => json!("0x2105"),
                "eth_getCode" => json!("0x6080604052"),
                "eth_call" => {
                    let c = &params[0];
                    json!(market.eth_call(c["to"].as_str()?, c["data"].as_str()?))
                }
                _ => return None,
            })
        });
        let provider = PinnedChainProvider::unix_socket(socket.path(), Some(socket.uid())).unwrap();
        let verifier = BaseUsdcVerifier::from_resolved(&resolve(None, Some(&provider)).unwrap(), 2).unwrap();
        (FlashArbAdapter::new(FlashArbConfig::default(), verifier).unwrap(), socket, dir)
    }

    fn offline() -> FlashArbAdapter {
        let verifier = BaseUsdcVerifier::new("http://127.0.0.1:8545", 2).unwrap();
        FlashArbAdapter::new(FlashArbConfig::default(), verifier).unwrap()
    }

    #[test]
    fn constructor_rejects_degenerate_config() {
        let v = || BaseUsdcVerifier::new("http://127.0.0.1:8545", 2).unwrap();
        let cfg = FlashArbConfig::default;
        for bad in [
            FlashArbConfig { agent_id: " ".into(), ..cfg() },
            FlashArbConfig { min_profit_musd_micros: 0, ..cfg() },
            FlashArbConfig { ttl_seconds: 0, ..cfg() },
            FlashArbConfig { loan_amount_usdc_micros: 0, ..cfg() },
            FlashArbConfig { loan_amount_usdc_micros: u64::MAX, ..cfg() },
        ] {
            assert!(FlashArbAdapter::new(bad, v()).is_err());
        }
    }

    #[test]
    fn aerodrome_calldata_is_get_amounts_out_with_one_volatile_route() {
        let d = offline()
            .build_dex_calldata(AERODROME_ROUTER, BASE_USDC, WETH, 100_000_000)
            .unwrap();
        assert!(d.starts_with("0x5509a1ac"));
        assert_eq!(d.len(), 2 + 8 + 64 * 7); // amountIn, offset, len, from, to, stable, factory
        let w = |i: usize| &d[10 + i * 64..10 + (i + 1) * 64];
        assert_eq!(u64::from_str_radix(w(0).trim_start_matches('0'), 16).unwrap(), 100_000_000);
        assert_eq!(w(1), format!("{:064x}", 0x40)); // offset to the route array
        assert_eq!(w(2), format!("{:064x}", 1)); // one route
        assert!(w(3).ends_with(&BASE_USDC[2..].to_lowercase()));
        assert!(w(4).ends_with(&WETH[2..]));
        assert_eq!(w(5), format!("{:064x}", 0)); // stable = false
        assert!(w(6).ends_with(&AERODROME_FACTORY[2..]));
    }

    #[test]
    fn uniswap_calldata_is_quote_exact_input_single_at_the_500_tier() {
        let a = offline();
        let d = a.build_dex_calldata(UNISWAP_V3_ROUTER, BASE_USDC, WETH, 7).unwrap();
        assert!(d.starts_with("0xc6a5026a"));
        assert_eq!(d.len(), 2 + 8 + 64 * 5);
        assert_eq!(&d[10 + 3 * 64..10 + 4 * 64], format!("{:064x}", 500));
        // The quote goes to the QuoterV2; the SwapRouter02 would revert.
        let q = a.build_price_query(UNISWAP_V3_ROUTER, BASE_USDC, WETH, 7).unwrap();
        assert_eq!(q[0]["to"], UNISWAP_V3_QUOTER);
        assert!(q[0]["from"].is_null());
    }

    #[test]
    fn calldata_refuses_unknown_venue_and_malformed_token() {
        let a = offline();
        assert!(a.build_dex_calldata("0x33d4fc5a1d7d3e5f0a5d6c7b8e9f0a1b2c3d4e5f", BASE_USDC, WETH, 1).is_err());
        assert!(a.build_dex_calldata(AERODROME_ROUTER, "0x1234", WETH, 1).is_err());
        assert!(a.build_dex_calldata(AERODROME_ROUTER, "833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", WETH, 1).is_err());
    }

    #[test]
    fn empty_eth_call_result_is_an_error_not_a_zero_quote() {
        for dex in [AERODROME_ROUTER, UNISWAP_V3_ROUTER] {
            assert!(FlashArbAdapter::decode_amount_out(dex, &json!("0x")).is_err());
            assert!(FlashArbAdapter::decode_amount_out(dex, &json!(null)).is_err());
            assert!(FlashArbAdapter::decode_amount_out(dex, &json!("0xzz")).is_err());
        }
    }

    #[test]
    fn decode_reads_the_right_word_per_venue() {
        let uni = json!(format!("0x{:064x}{:064x}{:064x}{:064x}", 42, 9, 9, 9));
        assert_eq!(FlashArbAdapter::decode_amount_out(UNISWAP_V3_ROUTER, &uni).unwrap(), 42);
        let aero = json!(format!("0x{:064x}{:064x}{:064x}{:064x}", 0x20, 2, 100, 42));
        assert_eq!(FlashArbAdapter::decode_amount_out(AERODROME_ROUTER, &aero).unwrap(), 42);
        // Declared length disagrees with the payload: not an amounts array.
        let lying = json!(format!("0x{:064x}{:064x}{:064x}{:064x}", 0x20, 3, 100, 42));
        assert!(FlashArbAdapter::decode_amount_out(AERODROME_ROUTER, &lying).is_err());
        // Does not fit u64.
        let huge = json!(format!("0x{:064x}", u128::MAX));
        assert!(FlashArbAdapter::decode_amount_out(UNISWAP_V3_ROUTER, &huge).is_err());
    }

    #[test]
    fn a_flat_market_reports_its_real_negative_edge_and_no_opportunity() {
        let (a, _s, _d) = adapter(Market::flat());
        let (opps, edges) = a.scan_all_pairs().unwrap();
        assert!(opps.is_empty());
        assert_eq!(edges.len(), 2);
        for e in &edges {
            // Round-trip through two pools costs both fees: a real negative number,
            // not the old constant "-gas".
            let gross = e.token_edge_micros.unwrap();
            assert!(gross < 0, "{gross}");
            assert_eq!(e.robust_net_micros, gross - ESTIMATED_GAS_COST_USDC_MICROS);
        }
    }

    #[test]
    fn a_dislocation_is_found_in_the_right_direction_and_costs_the_live_fee() {
        let (a, _s, _d) = adapter(Market { aero_usd: 3_200, ..Market::flat() });
        let (opps, edges) = a.scan_all_pairs().unwrap();
        assert_eq!(opps.len(), 1);
        assert_eq!(opps[0].dex_pair, "Uniswap→Aerodrome"); // buy WETH cheap on Uniswap
        assert_eq!(opps[0].modeled_profit_usdc_micros, opps[0].gross_profit_usdc_micros as i64 - 500);
        assert_eq!(
            edges.iter().map(|e| e.robust_net_micros).max(),
            Some(opps[0].modeled_profit_usdc_micros)
        );

        // 5 bps on a $100 loan is $0.05, read from the chain rather than assumed.
        let (a, _s, _d) = adapter(Market { aero_usd: 3_200, fee_1e18: 5 * 10u128.pow(14), ..Market::flat() });
        let (opps, _) = a.scan_all_pairs().unwrap();
        assert_eq!(opps[0].network_cost_usdc_micros, 500 + 50_000);
    }

    #[test]
    fn a_dead_quoter_fails_the_scan_instead_of_booking_no_edge() {
        let (a, _s, _d) = adapter(Market { dead_quoter: true, ..Market::flat() });
        assert!(a.scan_all_pairs().is_err());
    }

    #[test]
    fn an_implausible_flash_fee_fails_the_scan() {
        let (a, _s, _d) = adapter(Market { fee_1e18: 2 * 10u128.pow(18), ..Market::flat() });
        assert!(a.flash_loan_fee_bps().is_err());
    }

    #[test]
    fn pair_labels_are_correct() {
        assert_eq!(pair_as_str(DexPair::AerodromeToUniswap), "Aerodrome→Uniswap");
        assert_eq!(pair_as_str(DexPair::UniswapToAerodrome), "Uniswap→Aerodrome");
    }

    #[test]
    fn opportunity_id_is_stable_for_same_inputs() {
        let args = ["agent-1", "Aerodrome→Uniswap", "100000000", "1234567890"];
        assert_eq!(stable_id("flasharb", &args), stable_id("flasharb", &args));
        let other = ["agent-1", "Aerodrome→Uniswap", "200000000", "1234567890"];
        assert_ne!(stable_id("flasharb", &args), stable_id("flasharb", &other));
    }
}
