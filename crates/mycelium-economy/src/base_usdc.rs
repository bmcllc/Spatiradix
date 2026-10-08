//! Read-only Base/USDC payment verification.
//!
//! This module intentionally exposes no signing or broadcast operation.
//! It only uses eth_chainId, eth_blockNumber, eth_getCode and
//! eth_getTransactionReceipt.

use crate::{
    chain_provider::{ChainTransport, PinnedChainProvider, ResolvedChainProvider},
    EconomyError, Result,
};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;

pub const BASE_CHAIN_ID: u64 = 8453;
pub const BASE_USDC: &str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
/// Canonical USDC decimals. Kept next to the contract address so a typed
/// asset identity can never be built from the address alone.
pub const BASE_USDC_DECIMALS: u8 = 6;
pub const ERC20_TRANSFER_TOPIC: &str =
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseAnchor {
    pub chain_id: u64,
    pub block_number: u64,
    pub block_hash: String,
    pub block_timestamp_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseUsdcVerification {
    pub verified: bool,
    pub rpc: String,
    /// True when the endpoint's identity was enforced by the kernel, i.e. a
    /// pinned Unix domain socket whose ownership was checked. False only for
    /// the dev-only loopback HTTP override, which authenticates nothing.
    pub provider_identity_verified: bool,
    pub chain_id: u64,
    pub transaction_hash: String,
    pub block_number: u64,
    pub block_hash: String,
    pub block_timestamp_unix: u64,
    pub latest_block: u64,
    pub confirmations: u64,
    pub token: String,
    pub recipient: String,
    pub expected_raw: u64,
    pub matched_raw: u64,
    pub matching_log_index: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct BaseUsdcVerifier {
    rpc: String,
    /// `None` is the legacy, unpinned constructor. Every RPC goes through
    /// [`Self::rpc_call`], which refuses to talk to an unpinned endpoint, and
    /// the pinned provider is what decides the transport.
    pinned: Option<PinnedChainProvider>,
    client: Client,
    min_confirmations: u64,
}

/// One ERC-20 `Transfer` log this build could classify, read straight off a
/// receipt.
///
/// A value, not an authority: what it means economically is decided by two
/// registry lookups against the operator's controlled set, exactly as P1
/// decided it for [`crate::boundary::BoundaryEvidence`]. It is public because
/// it is the raw chain fact a [`TransactionLogScan`] enumerates, and it is
/// worthless alone — a scan with no [`Self::transfers`] entries is a scan that
/// saw no transfer, which is a different claim from a scan that was never made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ObservedTransfer {
    /// `None` when the receipt reported no `logIndex` for this log. A gas-free
    /// transaction may contain two identical transfers, so without the index
    /// this fact cannot be named or bound to stored evidence — the same rule
    /// [`crate::event_id`] applies, reported from here rather than defaulted.
    pub log_index: Option<u64>,
    /// The emitting contract, always `BASE_USDC` for anything that made it into
    /// a scan's transfer list.
    pub token: String,
    pub from_address: String,
    pub to_address: String,
    pub amount_raw: u64,
}

/// The chain facts about a transaction the scan context needs, assembled by
/// [`BaseUsdcVerifier::scan_transaction`] after every gate has passed.
#[derive(Debug, Clone)]
pub(crate) struct TransactionScanContext {
    pub chain_id: u64,
    pub tx_hash: String,
    pub block_number: u64,
    pub block_hash: String,
    pub block_timestamp_unix: u64,
    pub confirmations: u64,
    pub provider: String,
    pub provider_identity_verified: bool,
}

/// Everything one confirmed transaction did, as far as this build can read it.
///
/// See [`BaseUsdcVerifier::scan_transaction`] for why this exists and why
/// [`Self::exhaustive`] is the field that decides whether a leg set built from
/// it may be called complete.
#[derive(Debug, Clone, Serialize)]
pub struct TransactionLogScan {
    chain_id: u64,
    tx_hash: String,
    block_number: u64,
    block_hash: String,
    block_timestamp_unix: u64,
    confirmations: u64,
    provider: String,
    provider_identity_verified: bool,
    /// `false` when at least one log could not be classified. See the table on
    /// [`BaseUsdcVerifier::scan_transaction`].
    exhaustive: bool,
    /// One line per log this build could not place, so an operator reading an
    /// incomplete settlement can see *which* log blocked it.
    unclassified: Vec<String>,
    transfers: Vec<ObservedTransfer>,
    gas_used: u64,
    effective_gas_price_wei: u128,
    l1_fee_wei: u128,
    /// P4.6. Whether the receipt actually reported an L1 data charge, as
    /// opposed to the scan having found nothing and stored zero.
    ///
    /// These are different claims and the difference is load-bearing: on a chain
    /// that always reports `l1Fee`, a missing field is a malformed receipt; on a
    /// chain that never reports it, zero is a true statement and a conversion
    /// that assumed zero would be a conversion of a number nobody read. So the
    /// scan says which it is, and P4.6 refuses to convert a native cost whose L1
    /// component was not reported rather than assuming it away.
    l1_fee_reported: bool,
}

impl TransactionLogScan {
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub fn tx_hash(&self) -> &str {
        &self.tx_hash
    }

    pub fn block_number(&self) -> u64 {
        self.block_number
    }

    pub fn block_hash(&self) -> &str {
        &self.block_hash
    }

    pub fn block_timestamp_unix(&self) -> u64 {
        self.block_timestamp_unix
    }

    pub fn confirmations(&self) -> u64 {
        self.confirmations
    }

    /// The endpoint the facts came from.
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// True when the endpoint's identity was enforced by the kernel. Always
    /// true for a scan produced through the pinned path; the field exists so an
    /// audit log does not have to take it on faith.
    pub fn provider_identity_verified(&self) -> bool {
        self.provider_identity_verified
    }

    /// Whether every log in the receipt was classified. **A settlement may only
    /// claim a complete leg set when this is `true`.**
    pub fn exhaustive(&self) -> bool {
        self.exhaustive
    }

    /// The logs that could not be classified, in receipt order. Empty exactly
    /// when [`Self::exhaustive`] is `true`.
    pub fn unclassified(&self) -> &[String] {
        &self.unclassified
    }

    /// Every `Transfer` log of `BASE_USDC` this receipt carried.
    pub fn transfers(&self) -> &[ObservedTransfer] {
        &self.transfers
    }

    pub fn gas_used(&self) -> u64 {
        self.gas_used
    }

    pub fn effective_gas_price_wei(&self) -> u128 {
        self.effective_gas_price_wei
    }

    /// The separate L1 data charge, in wei, or `0` when this receipt reports
    /// none. Never converted and never estimated — see
    /// [`Self::effective_gas_price_wei`] on why an absent field is a statement
    /// about the receipt rather than about the cost.
    pub fn l1_fee_wei(&self) -> u128 {
        self.l1_fee_wei
    }

    /// P4.6. Whether the receipt reported an L1 data charge at all.
    ///
    /// `l1_fee_wei() == 0` is not the same claim. Use this to refuse a
    /// conversion rather than to assume the charge was free.
    pub fn l1_fee_reported(&self) -> bool {
        self.l1_fee_reported
    }

    /// P4.6. The block this transaction settled in, as a first-class value.
    ///
    /// [`Self::block_number`] and [`Self::block_timestamp_unix`] were on the
    /// scan all along; what was missing was any type that carried them
    /// together, so every layer above had to choose two accessors and invent its
    /// own struct — and the layer that converts wei into an economic unit had no
    /// time anchor to choose a price against at all. A price selected *after*
    /// the fact is a price picked to suit the answer, so the anchor is now part
    /// of the type that carries it onward.
    pub fn anchor(&self) -> BlockAnchor {
        BlockAnchor {
            chain_id: self.chain_id,
            block_number: self.block_number,
            block_hash: self.block_hash.clone(),
            block_timestamp_unix: self.block_timestamp_unix,
            confirmations: self.confirmations,
        }
    }
}

/// Where a transaction settled: the block, the hash of that block, the block's
/// own timestamp, and how deep it was at the moment of the read.
///
/// Every field is a chain fact, taken from a receipt whose block was confirmed
/// canonical against `eth_getBlockByNumber` before it got here, so the four
/// agree with each other by construction. The timestamp is the *block's*, not
/// the node's clock: a local clock would make the price window depend on the
/// machine doing the reading, which is exactly the property a settlement must
/// not have.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BlockAnchor {
    chain_id: u64,
    block_number: u64,
    block_hash: String,
    block_timestamp_unix: u64,
    confirmations: u64,
}

impl BlockAnchor {
    /// The only constructor, and it takes the read rather than the fields: an
    /// anchor assembled from four caller-supplied numbers would be a claim, not
    /// an anchor.
    pub fn from_scan(scan: &TransactionLogScan) -> Self {
        scan.anchor()
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub fn block_number(&self) -> u64 {
        self.block_number
    }

    pub fn block_hash(&self) -> &str {
        &self.block_hash
    }

    /// The block's own timestamp, in unix seconds.
    pub fn block_timestamp_unix(&self) -> u64 {
        self.block_timestamp_unix
    }

    pub fn confirmations(&self) -> u64 {
        self.confirmations
    }
}

impl BaseUsdcVerifier {
    /// Legacy constructor, kept for callers that already hold an endpoint.
    ///
    /// It still refuses a non-loopback endpoint — that part is load-bearing
    /// for a read-only verifier and stays. But an endpoint reaching this
    /// constructor is **not pinned**, and an unpinned verifier refuses to make
    /// any RPC call: loopback TCP is not an identity. Build one with
    /// [`Self::from_resolved`] from a pinned provider instead.
    pub fn new(rpc: impl Into<String>, min_confirmations: u64) -> Result<Self> {
        let rpc = rpc.into();
        if !rpc.starts_with("http://127.0.0.1:")
            && !rpc.starts_with("http://localhost:")
            && !rpc.starts_with("https://127.0.0.1:")
            && !rpc.starts_with("https://localhost:")
        {
            return Err(EconomyError::Invalid(
                "RV0 Base verifier requires a loopback/local RPC endpoint".into(),
            ));
        }
        let client = Client::builder()
            .timeout(Duration::from_secs(8))
            .build()
            .map_err(|e| EconomyError::Invalid(format!("RPC client: {e}")))?;
        Ok(Self {
            pinned: None,
            rpc,
            client,
            min_confirmations,
        })
    }

    /// Entry point of the trust boundary. Fail-closed: the provider must have
    /// been pinned out-of-band ([`crate::chain_provider`]), and a Unix socket
    /// provider must additionally pass the kernel ownership/permission check
    /// before a single byte is written.
    ///
    /// WHAT THIS DEFENDS AGAINST: any process that can bind a loopback TCP
    /// port can no longer pass as the trusted provider. The endpoint comes
    /// from the payment policy file or from the dev-only environment override,
    /// never from argv, and a policy pin must be a Unix domain socket whose
    /// inode ownership and permission bits the kernel checks on `connect(2)`.
    /// Swapping the source of truth now requires writing the policy file, not
    /// winning a race for port 8546.
    ///
    /// WHAT THIS DOES NOT DEFEND AGAINST: an attacker with root or full host
    /// compromise; an attacker running as the same OS principal who can
    /// replace the binary, read the socket or write the policy file; a
    /// compromised upstream Base node; and the dev-only loopback override,
    /// which is unauthenticated by construction and says so in every
    /// verification record. No purely cryptographic scheme with a key in the
    /// same `$HOME` changes this — a same-principal attacker owns that key.
    /// Real hardening moves the key out of reach of the verifier's principal:
    /// TPM-held key, separate verifier host, quorum, or an external anchor.
    pub fn from_resolved(
        resolved: &ResolvedChainProvider,
        min_confirmations: u64,
    ) -> Result<Self> {
        let provider = &resolved.provider;
        // Re-validate at the boundary: a pin read from disk is only as good as
        // the checks applied to it right before it is used.
        provider.validate_shape()?;
        // The dev override may select a loopback HTTP endpoint. It is tolerated
        // only because the operator opted in explicitly, and every verification
        // it produces is marked identity-unverified. A policy pin never can be.
        let dev_loopback =
            resolved.is_dev_override() && !provider.identity_kernel_enforced();
        if !dev_loopback {
            provider.validate_policy_pin()?;
        }
        if provider.identity_kernel_enforced() {
            provider.verify_socket_identity()?;
        }
        let client = Client::builder()
            .timeout(Duration::from_secs(8))
            .build()
            .map_err(|e| EconomyError::Invalid(format!("RPC client: {e}")))?;
        Ok(Self {
            rpc: provider.endpoint().to_string(),
            pinned: Some(provider.clone()),
            client,
            min_confirmations,
        })
    }

    pub fn provider_identity_verified(&self) -> bool {
        self.pinned
            .as_ref()
            .map(PinnedChainProvider::identity_kernel_enforced)
            .unwrap_or(false)
    }

    pub fn endpoint(&self) -> &str {
        &self.rpc
    }

    pub fn anchor(&self) -> Result<BaseAnchor> {
        let chain_id = hex_u64(&self.rpc_call("eth_chainId", json!([]))?)?;
        if chain_id != BASE_CHAIN_ID {
            return Err(EconomyError::Invalid(format!(
                "wrong chain id: expected {BASE_CHAIN_ID}, got {chain_id}"
            )));
        }
        let block_number =
            hex_u64(&self.rpc_call("eth_blockNumber", json!([]))?)?;
        let block = self.rpc_call(
            "eth_getBlockByNumber",
            json!([format!("0x{block_number:x}"), false]),
        )?;
        let block_hash = block
            .get("hash")
            .and_then(Value::as_str)
            .ok_or_else(|| EconomyError::Invalid(
                "anchor block missing hash".into(),
            ))?
            .to_ascii_lowercase();
        validate_hash32("anchor block hash", &block_hash)?;
        let block_timestamp_unix = hex_u64(
            block
                .get("timestamp")
                .ok_or_else(|| EconomyError::Invalid(
                    "anchor block missing timestamp".into(),
                ))?,
        )?;
        Ok(BaseAnchor {
            chain_id,
            block_number,
            block_hash,
            block_timestamp_unix,
        })
    }

    pub fn health(&self) -> Result<Value> {
        let chain_id = hex_u64(&self.rpc_call("eth_chainId", json!([]))?)?;
        let latest = hex_u64(&self.rpc_call("eth_blockNumber", json!([]))?)?;
        let code = self.rpc_call("eth_getCode", json!([BASE_USDC, "latest"]))?;
        let code = code
            .as_str()
            .ok_or_else(|| EconomyError::Invalid("eth_getCode was not a string".into()))?;
        if chain_id != BASE_CHAIN_ID {
            return Err(EconomyError::Invalid(format!(
                "wrong chain id: expected {BASE_CHAIN_ID}, got {chain_id}"
            )));
        }
        if code == "0x" || code == "0x0" {
            return Err(EconomyError::Invalid(
                "Base USDC address has no bytecode".into(),
            ));
        }
        Ok(json!({
            "rpc": self.rpc,
            "read_only": true,
            "provider_identity_verified": self.provider_identity_verified(),
            "chain_id": chain_id,
            "latest_block": latest,
            "usdc": BASE_USDC,
            "usdc_code_present": true,
            "broadcast_supported_by_verifier": false
        }))
    }

    pub fn verify_transfer(
        &self,
        tx_hash: &str,
        recipient: &str,
        expected_raw: u64,
    ) -> Result<BaseUsdcVerification> {
        validate_hash32("tx_hash", tx_hash)?;
        let recipient = normalize_address(recipient)?;
        if expected_raw == 0 {
            return Err(EconomyError::Invalid(
                "expected USDC amount must be > 0".into(),
            ));
        }

        let chain_id = hex_u64(&self.rpc_call("eth_chainId", json!([]))?)?;
        if chain_id != BASE_CHAIN_ID {
            return Err(EconomyError::Invalid(format!(
                "wrong chain id: expected {BASE_CHAIN_ID}, got {chain_id}"
            )));
        }

        let receipt = self.rpc_call(
            "eth_getTransactionReceipt",
            json!([tx_hash]),
        )?;
        if receipt.is_null() {
            return Err(EconomyError::Invalid(
                "transaction receipt not found".into(),
            ));
        }

        let status = receipt
            .get("status")
            .ok_or_else(|| EconomyError::Invalid("receipt missing status".into()))?;
        if hex_u64(status)? != 1 {
            return Err(EconomyError::Invalid(
                "transaction did not succeed".into(),
            ));
        }

        let block_number = hex_u64(
            receipt
                .get("blockNumber")
                .ok_or_else(|| EconomyError::Invalid(
                    "receipt missing blockNumber".into(),
                ))?,
        )?;
        let block = self.rpc_call(
            "eth_getBlockByNumber",
            json!([format!("0x{block_number:x}"), false]),
        )?;
        let block_hash = block
            .get("hash")
            .and_then(Value::as_str)
            .ok_or_else(|| EconomyError::Invalid(
                "block missing hash".into(),
            ))?
            .to_ascii_lowercase();
        let receipt_block_hash = receipt
            .get("blockHash")
            .and_then(Value::as_str)
            .ok_or_else(|| EconomyError::Invalid(
                "receipt missing blockHash".into(),
            ))?;
        if !eq_hex(&block_hash, receipt_block_hash) {
            return Err(EconomyError::Invalid(
                "transaction receipt is not canonical for its block".into(),
            ));
        }
        let block_timestamp_unix = hex_u64(
            block
                .get("timestamp")
                .ok_or_else(|| EconomyError::Invalid(
                    "block missing timestamp".into(),
                ))?,
        )?;
        let latest_block = hex_u64(
            &self.rpc_call("eth_blockNumber", json!([]))?
        )?;
        let confirmations = latest_block
            .saturating_sub(block_number)
            .saturating_add(1);
        if confirmations < self.min_confirmations {
            return Err(EconomyError::Invalid(format!(
                "not enough confirmations: have {confirmations}, need {}",
                self.min_confirmations
            )));
        }

        let logs = receipt
            .get("logs")
            .and_then(Value::as_array)
            .ok_or_else(|| EconomyError::Invalid("receipt missing logs".into()))?;

        let mut matched_raw = 0u64;
        let mut matching_log_index = None;

        for log in logs {
            let address = log
                .get("address")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if !eq_hex(address, BASE_USDC) {
                continue;
            }

            let topics = match log.get("topics").and_then(Value::as_array) {
                Some(v) if v.len() >= 3 => v,
                _ => continue,
            };
            let topic0 = topics[0].as_str().unwrap_or_default();
            if !eq_hex(topic0, ERC20_TRANSFER_TOPIC) {
                continue;
            }
            let to_topic = topics[2].as_str().unwrap_or_default();
            let to_addr = topic_address(to_topic)?;
            if !eq_hex(&to_addr, &recipient) {
                continue;
            }

            let data = log
                .get("data")
                .and_then(Value::as_str)
                .unwrap_or("0x0");
            let amount = hex_u128_str(data)?;
            if amount > u64::MAX as u128 {
                return Err(EconomyError::Invalid(
                    "USDC transfer exceeds u64".into(),
                ));
            }
            let amount = amount as u64;
            if amount == expected_raw {
                matched_raw = amount;
                matching_log_index = log
                    .get("logIndex")
                    .and_then(Value::as_str)
                    .map(parse_hex_u64)
                    .transpose()?;
                break;
            }
        }

        if matched_raw != expected_raw {
            return Err(EconomyError::Invalid(format!(
                "no exact USDC Transfer to {recipient} for {expected_raw} raw units"
            )));
        }

        Ok(BaseUsdcVerification {
            verified: true,
            rpc: self.rpc.clone(),
            provider_identity_verified: self.provider_identity_verified(),
            chain_id,
            transaction_hash: tx_hash.to_ascii_lowercase(),
            block_number,
            block_hash,
            block_timestamp_unix,
            latest_block,
            confirmations,
            token: BASE_USDC.to_ascii_lowercase(),
            recipient,
            expected_raw,
            matched_raw,
            matching_log_index,
        })
    }

    /// Reads the WHOLE receipt of one transaction and returns everything a
    /// settlement needs to prove it saw every leg.
    ///
    /// # Why a second read and not a wider `verify_transfer`
    ///
    /// [`Self::verify_transfer`] answers "is there a Transfer to this recipient
    /// for this amount", and it is used by every existing gate. That question
    /// is *per-leg* and, answered alone, it is exactly the shape of the bug
    /// P4.5e exists to close: a node that only ever asks about the inflow can
    /// confirm the inflow forever and never learn that an outflow existed.
    /// Completeness needs the opposite question — "what did this transaction
    /// do?" — and only the whole log list answers it.
    ///
    /// # Why the type cannot be forged
    ///
    /// Private fields, no `Deserialize`, and one constructor,
    /// [`Self::from_receipt`], which is `pub(crate)` and is called from exactly
    /// one place: [`Self::scan_transaction`], after the same chain-id, block,
    /// confirmation and pinned-identity checks `verify_transfer` performs. A
    /// JSON document cannot become a scan and a caller cannot assemble one out
    /// of a list of transfers it likes.
    ///
    /// # `exhaustive` is the load-bearing field
    ///
    /// `false` means the read could not classify every log in the receipt, so
    /// the set of transfers here is *not* the set of transfers that happened.
    /// Every log is placed in exactly one bucket:
    ///
    /// | log | bucket | effect |
    /// |-----|--------|--------|
    /// | `Transfer` on `BASE_USDC`, readable amount | a leg | listed in `transfers` |
    /// | `Transfer` on any other contract | unidentified | `exhaustive = false` |
    /// | `Transfer` on `BASE_USDC`, amount unreadable or above `u64` | unidentified | `exhaustive = false` |
    /// | anything else (a swap, a sync, a custom event) | not a transfer | ignored |
    ///
    /// A transfer of an unidentified token into a controlled address is a real
    /// economic leg this build cannot price, so refusing to call the set
    /// complete is the only honest answer. When the network gains a second
    /// identified asset this classification must be revisited, and until then
    /// it fails closed rather than assuming it away.
    pub fn scan_transaction(&self, tx_hash: &str) -> Result<TransactionLogScan> {
        validate_hash32("tx_hash", tx_hash)?;
        let chain_id = hex_u64(&self.rpc_call("eth_chainId", json!([]))?)?;
        if chain_id != BASE_CHAIN_ID {
            return Err(EconomyError::Invalid(format!(
                "wrong chain id: expected {BASE_CHAIN_ID}, got {chain_id}"
            )));
        }
        let receipt =
            self.rpc_call("eth_getTransactionReceipt", json!([tx_hash]))?;
        if receipt.is_null() {
            return Err(EconomyError::Invalid(
                "transaction receipt not found".into(),
            ));
        }
        let status = receipt
            .get("status")
            .ok_or_else(|| EconomyError::Invalid("receipt missing status".into()))?;
        if hex_u64(status)? != 1 {
            return Err(EconomyError::Invalid(
                "transaction did not succeed".into(),
            ));
        }
        let block_number = hex_u64(
            receipt
                .get("blockNumber")
                .ok_or_else(|| EconomyError::Invalid("receipt missing blockNumber".into()))?,
        )?;
        let block = self.rpc_call(
            "eth_getBlockByNumber",
            json!([format!("0x{block_number:x}"), false]),
        )?;
        let block_hash = block
            .get("hash")
            .and_then(Value::as_str)
            .ok_or_else(|| EconomyError::Invalid("block missing hash".into()))?
            .to_ascii_lowercase();
        let receipt_block_hash = receipt
            .get("blockHash")
            .and_then(Value::as_str)
            .ok_or_else(|| EconomyError::Invalid("receipt missing blockHash".into()))?;
        if !eq_hex(&block_hash, receipt_block_hash) {
            return Err(EconomyError::Invalid(
                "transaction receipt is not canonical for its block".into(),
            ));
        }
        let block_timestamp_unix = hex_u64(
            block
                .get("timestamp")
                .ok_or_else(|| EconomyError::Invalid("block missing timestamp".into()))?,
        )?;
        let latest_block =
            hex_u64(&self.rpc_call("eth_blockNumber", json!([]))?)?;
        let confirmations = latest_block
            .saturating_sub(block_number)
            .saturating_add(1);
        if confirmations < self.min_confirmations {
            return Err(EconomyError::Invalid(format!(
                "not enough confirmations: have {confirmations}, need {}",
                self.min_confirmations
            )));
        }
        Self::from_receipt(&receipt, TransactionScanContext {
            chain_id,
            tx_hash: tx_hash.to_ascii_lowercase(),
            block_number,
            block_hash,
            block_timestamp_unix,
            confirmations,
            provider: self.rpc.clone(),
            provider_identity_verified: self.provider_identity_verified(),
        })
    }

    /// The one place a [`TransactionLogScan`] is built. `pub(crate)` so the
    /// only route is [`Self::scan_transaction`], and it is called only after
    /// every gate above has run.
    pub(crate) fn from_receipt(
        receipt: &Value,
        ctx: TransactionScanContext,
    ) -> Result<TransactionLogScan> {
        let logs = receipt
            .get("logs")
            .and_then(Value::as_array)
            .ok_or_else(|| EconomyError::Invalid("receipt missing logs".into()))?;
        let mut transfers = Vec::new();
        let mut unclassified: Vec<String> = Vec::new();
        for log in logs {
            let topics = log.get("topics").and_then(Value::as_array);
            let is_transfer = topics
                .and_then(|t| t.first())
                .and_then(Value::as_str)
                .map(|t| eq_hex(t, ERC20_TRANSFER_TOPIC))
                .unwrap_or(false);
            if !is_transfer {
                continue;
            }
            let address = log
                .get("address")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let topics = topics.cloned().unwrap_or_default();
            if topics.len() < 3 {
                unclassified.push(format!(
                    "log {}: Transfer with {} topics",
                    log.get("logIndex").and_then(Value::as_str).unwrap_or("?"),
                    topics.len()
                ));
                continue;
            }
            if !eq_hex(address, BASE_USDC) {
                unclassified.push(format!(
                    "log {}: Transfer of unidentified token {address}",
                    log.get("logIndex").and_then(Value::as_str).unwrap_or("?")
                ));
                continue;
            }
            let from = topic_address(topics[1].as_str().unwrap_or_default())?;
            let to = topic_address(topics[2].as_str().unwrap_or_default())?;
            let raw = hex_u128_str(
                log.get("data")
                    .and_then(Value::as_str)
                    .unwrap_or("0x0"),
            )?;
            let Some(amount_raw) = u64::try_from(raw).ok() else {
                unclassified.push(format!(
                    "log {}: transfer of {raw} raw units is above u64",
                    log.get("logIndex").and_then(Value::as_str).unwrap_or("?")
                ));
                continue;
            };
            transfers.push(ObservedTransfer {
                log_index: log
                    .get("logIndex")
                    .and_then(Value::as_str)
                    .map(parse_hex_u64)
                    .transpose()?,
                token: BASE_USDC.to_ascii_lowercase(),
                from_address: from,
                to_address: to,
                amount_raw,
            });
        }

        // Gas. `gasUsed` is the standard field; `l1Fee` is what an OP-stack
        // receipt carries for the L1 data charge. Both are optional in the
        // receipt shape, and their absence is a statement about *this receipt*,
        // not about the cost: a chain that reports no separate L1 fee reports
        // zero for it, which is a true statement on that chain and a false one
        // on another. It is therefore never used to justify a comparable USD
        // figure — see `VerifiedSettlement::comparable_net_value_micros`.
        let gas_used = hex_u64(
            receipt
                .get("gasUsed")
                .ok_or_else(|| EconomyError::Invalid("receipt missing gasUsed".into()))?,
        )?;
        let effective_gas_price_wei = receipt
            .get("effectiveGasPrice")
            .or_else(|| receipt.get("gasPrice"))
            .map(|v| hex_u128_str(v.as_str().unwrap_or("0x0")))
            .transpose()?
            .unwrap_or(0);
        let l1_fee_wei = receipt
            .get("l1Fee")
            .or_else(|| receipt.get("l1FeeWei"))
            .map(|v| hex_u128_str(v.as_str().unwrap_or("0x0")))
            .transpose()?
            .unwrap_or(0);
        let l1_fee_reported = receipt
            .get("l1Fee")
            .or_else(|| receipt.get("l1FeeWei"))
            .is_some();

        Ok(TransactionLogScan {
            chain_id: ctx.chain_id,
            tx_hash: ctx.tx_hash,
            block_number: ctx.block_number,
            block_hash: ctx.block_hash,
            block_timestamp_unix: ctx.block_timestamp_unix,
            confirmations: ctx.confirmations,
            provider: ctx.provider,
            provider_identity_verified: ctx.provider_identity_verified,
            exhaustive: unclassified.is_empty(),
            unclassified,
            transfers,
            gas_used,
            effective_gas_price_wei,
            l1_fee_wei,
            l1_fee_reported,
        })
    }

    /// The single choke point every chain read goes through. Two invariants
    /// live here and nowhere else: the read-only method allowlist, and the
    /// pinned-provider requirement.
    pub(crate) fn rpc_call(&self, method: &str, params: Value) -> Result<Value> {
        // Keep an explicit allowlist so this verifier can never become a
        // transaction broadcaster by accepting arbitrary method names.
        // `eth_call` is read-only: it simulates a contract call without
        // broadcasting or changing state. The verifier pins the endpoint
        // through the kernel-enforced Unix socket identity, so the result
        // is trusted only when the provider is pinned.
        match method {
            "eth_chainId"
            | "eth_blockNumber"
            | "eth_getCode"
            | "eth_getTransactionReceipt"
            | "eth_getTransactionByHash"
            | "eth_getBlockByNumber"
            | "eth_call" => {}
            _ => {
                return Err(EconomyError::Invalid(format!(
                    "RPC method not allowed by read-only verifier: {method}"
                )))
            }
        }

        // Fail closed on an unpinned source of truth. No policy pin, no
        // dev-only override, no request — there is no default endpoint to
        // degrade to.
        let pin = match &self.pinned {
            None => {
                return Err(EconomyError::ProviderUnpinned(format!(
                    "refusing {method} against unpinned endpoint {}: a loopback TCP port \
                     is not an identity. Pin a provider out-of-band with \
                     `mycelium-economy --home DIR payment-policy-pin-provider \
                     {}`, or set {} for tests only",
                    self.rpc,
                    crate::chain_provider::DEFAULT_PROVIDER_SOCKET_URI,
                    crate::chain_provider::DEV_PROVIDER_ENV
                )))
            }
            // A pinned unix socket must still own its identity at call time,
            // not only at construction time.
            Some(pin) => {
                if pin.identity_kernel_enforced() {
                    pin.verify_socket_identity()?;
                }
                pin
            }
        };
        let transport = pin.transport();

        // For eth_call, validate that params have the expected shape:
        // [{"to": address, "data": calldata, "from": null}, "latest" or block tag]
        // This prevents any attempt to pass a "from" address that could
        // suggest a state-changing call.
        if method == "eth_call" {
            if let Some(params_arr) = params.as_array() {
                if let Some(call_obj) = params_arr.first().and_then(|v| v.as_object()) {
                    if let Some(from) = call_obj.get("from") {
                        if from.as_str().map(|s| !s.is_empty()).unwrap_or(false) {
                            return Err(EconomyError::Invalid(
                                "eth_call with a non-null 'from' field is rejected; \
                                 the verifier is strictly read-only"
                                    .into(),
                            ));
                        }
                    }
                }
            }
        }

        let payload = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params
        });

        let body: Value = match transport {
            ChainTransport::UnixSocket => unix_rpc_call(&pin.socket_path()?, method, &payload)?,
            ChainTransport::LoopbackHttp => {
                let response = self
                    .client
                    .post(&self.rpc)
                    .json(&payload)
                    .send()
                    .map_err(|e| EconomyError::Invalid(format!("RPC {method}: {e}")))?;

                if !response.status().is_success() {
                    return Err(EconomyError::Invalid(format!(
                        "RPC {method} HTTP {}",
                        response.status()
                    )));
                }

                response
                    .json()
                    .map_err(|e| EconomyError::Invalid(format!("RPC JSON: {e}")))?
            }
        };

        if let Some(error) = body.get("error") {
            return Err(EconomyError::Invalid(format!(
                "RPC {method} error: {error}"
            )));
        }
        body.get("result")
            .cloned()
            .ok_or_else(|| EconomyError::Invalid(
                format!("RPC {method} missing result")
            ))
    }
}

/// Minimal HTTP/1.1 + JSON-RPC over a Unix domain socket.
///
/// `reqwest` has no Unix-socket transport and adding one is not worth a new
/// dependency for a read-only call, so the pinned transport is spoken here
/// directly. The request is a single POST with `Connection: close`, so the
/// response ends at EOF; `Content-Length` and `Transfer-Encoding: chunked` are
/// both understood.
fn unix_rpc_call(
    socket: &std::path::Path,
    method: &str,
    payload: &Value,
) -> Result<Value> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let body = serde_json::to_string(payload)
        .map_err(|e| EconomyError::Invalid(format!("RPC {method} encode: {e}")))?;
    let request = format!(
        "POST / HTTP/1.1\r\nHost: mycelium-verifier\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );

    let mut stream = UnixStream::connect(socket).map_err(|e| {
        EconomyError::Invalid(format!(
            "RPC {method} connect {}: {e}",
            socket.display()
        ))
    })?;
    let timeout = Some(Duration::from_secs(8));
    stream
        .set_read_timeout(timeout)
        .and_then(|()| stream.set_write_timeout(timeout))
        .map_err(|e| EconomyError::Invalid(format!("RPC {method} socket: {e}")))?;
    stream
        .write_all(request.as_bytes())
        .and_then(|()| stream.flush())
        .map_err(|e| EconomyError::Invalid(format!("RPC {method} write: {e}")))?;

    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|e| EconomyError::Invalid(format!("RPC {method} read: {e}")))?;
    let text = String::from_utf8(raw)
        .map_err(|_| EconomyError::Invalid(format!("RPC {method} response is not UTF-8")))?;
    let (head, body) = text.split_once("\r\n\r\n").ok_or_else(|| {
        EconomyError::Invalid(format!("RPC {method} returned a malformed HTTP response"))
    })?;

    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| {
            EconomyError::Invalid(format!("RPC {method} returned a malformed status line"))
        })?;
    if !(200..300).contains(&status) {
        return Err(EconomyError::Invalid(format!("RPC {method} HTTP {status}")));
    }

    let chunked = head.split("\r\n").any(|line| {
        let lower = line.to_ascii_lowercase();
        lower.starts_with("transfer-encoding:") && lower.contains("chunked")
    });
    let body = if chunked {
        decode_chunked(body)?
    } else {
        body.to_string()
    };

    serde_json::from_str(&body)
        .map_err(|e| EconomyError::Invalid(format!("RPC {method} JSON: {e}")))
}

fn decode_chunked(body: &str) -> Result<String> {
    let mut out = String::new();
    let mut rest = body;
    loop {
        let (size_line, tail) = rest.split_once("\r\n").ok_or_else(|| {
            EconomyError::Invalid("RPC chunked response is truncated".into())
        })?;
        let size = usize::from_str_radix(
            size_line.split(';').next().unwrap_or("").trim(),
            16,
        )
        .map_err(|_| EconomyError::Invalid("RPC chunked size is invalid".into()))?;
        if size == 0 {
            return Ok(out);
        }
        if tail.len() < size {
            return Err(EconomyError::Invalid(
                "RPC chunked response is truncated".into(),
            ));
        }
        out.push_str(&tail[..size]);
        rest = tail[size..].trim_start_matches("\r\n");
    }
}

fn eq_hex(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

pub fn normalize_address(value: &str) -> Result<String> {
    let v = value.strip_prefix("0x").unwrap_or(value);
    if v.len() != 40 || !v.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(EconomyError::Invalid(
            "recipient must be a 20-byte hex address".into(),
        ));
    }
    Ok(format!("0x{}", v.to_ascii_lowercase()))
}

/// Canonical 32-byte hex validator. This is the single implementation: the
/// boundary types in `boundary.rs` and the S1 adapter both reuse it instead of
/// carrying their own copy of the same rule.
pub fn validate_hash32(name: &str, value: &str) -> Result<()> {
    let v = value.strip_prefix("0x").unwrap_or(value);
    if v.len() != 64 || !v.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(EconomyError::Invalid(format!(
            "{name} must be a 32-byte hex value"
        )));
    }
    Ok(())
}

fn topic_address(topic: &str) -> Result<String> {
    let t = topic.strip_prefix("0x").unwrap_or(topic);
    if t.len() != 64 || !t.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(EconomyError::Invalid(
            "ERC20 address topic must be 32 bytes".into(),
        ));
    }
    Ok(format!("0x{}", t[24..].to_ascii_lowercase()))
}

fn parse_hex_u64(s: &str) -> Result<u64> {
    let h = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(if h.is_empty() { "0" } else { h }, 16)
        .map_err(|_| EconomyError::Invalid(format!("invalid hex u64: {s}")))
}

fn hex_u64(v: &Value) -> Result<u64> {
    let s = v
        .as_str()
        .ok_or_else(|| EconomyError::Invalid("expected hex string".into()))?;
    parse_hex_u64(s)
}

fn hex_u128_str(s: &str) -> Result<u128> {
    let h = s.strip_prefix("0x").unwrap_or(s);
    u128::from_str_radix(if h.is_empty() { "0" } else { h }, 16)
        .map_err(|_| EconomyError::Invalid(format!("invalid hex amount: {s}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chain_provider::{resolve, PinnedChainProvider, ProviderSource},
        rpc_test_server::FakeRpcSocket,
    };

    fn pinned(socket: &FakeRpcSocket) -> Result<BaseUsdcVerifier> {
        let provider = PinnedChainProvider::unix_socket(socket.path(), Some(socket.uid()))?;
        let resolved = resolve(None, Some(&provider))?;
        assert_eq!(resolved.source, ProviderSource::PolicyPin);
        BaseUsdcVerifier::from_resolved(&resolved, 2)
    }

    fn dev_loopback() -> Result<BaseUsdcVerifier> {
        let resolved = resolve(Some("http://127.0.0.1:8546"), None)?;
        assert!(resolved.is_dev_override());
        BaseUsdcVerifier::from_resolved(&resolved, 2)
    }

    #[test]
    fn extracts_topic_address() {
        let t = "0x0000000000000000000000001234567890abcdef1234567890abcdef12345678";
        assert_eq!(
            topic_address(t).unwrap(),
            "0x1234567890abcdef1234567890abcdef12345678"
        );
    }

    #[test]
    fn rejects_non_loopback_rpc() {
        let err = BaseUsdcVerifier::new("https://example.com", 2).unwrap_err();
        assert!(err.to_string().contains("loopback"));
    }

    #[test]
    fn transfer_topic_is_canonical_length() {
        assert_eq!(ERC20_TRANSFER_TOPIC.len(), 66);
        assert!(ERC20_TRANSFER_TOPIC.starts_with("0x"));
    }

    #[test]
    fn unpinned_endpoint_is_refused_and_never_contacted() {
        // The legacy constructor still accepts loopback, but an unpinned
        // verifier must not make a single call: loopback TCP is an address,
        // not an identity.
        let verifier = BaseUsdcVerifier::new("http://127.0.0.1:8546", 2).unwrap();
        let err = verifier.rpc_call("eth_chainId", json!([])).unwrap_err();
        assert!(matches!(err, EconomyError::ProviderUnpinned(_)));
        assert!(err.to_string().contains("not an identity"));
        assert!(err.to_string().contains("payment-policy-pin-provider"));
        assert!(!verifier.provider_identity_verified());
        assert!(verifier.anchor().is_err());
        assert!(verifier.health().is_err());
    }

    #[test]
    fn pinned_unix_socket_provider_serves_health() {
        let dir = tempfile::tempdir().unwrap();
        let server = FakeRpcSocket::bind(dir.path().join("verifier.sock"));
        let verifier = pinned(&server).unwrap();
        assert!(verifier.provider_identity_verified());
        let health = verifier.health().unwrap();
        assert_eq!(health["chain_id"], json!(BASE_CHAIN_ID));
        assert_eq!(health["provider_identity_verified"], json!(true));
        assert_eq!(health["broadcast_supported_by_verifier"], json!(false));
        assert_eq!(
            health["rpc"],
            json!(format!("unix://{}", server.path().display()))
        );
        assert!(server.requested_methods().contains(&"eth_getCode".to_string()));
    }

    #[test]
    fn provider_reporting_the_wrong_chain_id_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        // 1 = Ethereum mainnet, i.e. a provider that is not Base at all.
        let server = FakeRpcSocket::with_responses(
            dir.path().join("wrong-chain.sock"),
            vec![
                ("eth_chainId", json!("0x1")),
                ("eth_blockNumber", json!("0x64")),
                ("eth_getCode", json!("0x6080604052")),
            ],
        );
        let verifier = pinned(&server).unwrap();
        let err = verifier.health().unwrap_err();
        assert!(err.to_string().contains("wrong chain id"));
        assert!(err.to_string().contains("got 1"));
        assert!(verifier.anchor().is_err());
    }

    #[test]
    fn pinned_socket_identity_is_rechecked_before_every_call() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("verifier.sock");
        let server = FakeRpcSocket::bind(&path);
        let verifier = pinned(&server).unwrap();
        verifier.health().unwrap();
        let served_before = server.connections();

        // A provider replaced by a world-writable socket between calls must
        // stop the verifier even though the pin is unchanged.
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                &path,
                std::fs::Permissions::from_mode(0o777),
            )
            .unwrap();
        }
        let err = verifier.health().unwrap_err();
        assert!(err.to_string().contains("group/other-writable"));
        // Refused before the endpoint was opened: no request was sent to the
        // socket that now owns the path.
        assert_eq!(server.connections(), served_before);
    }

    #[test]
    fn dev_loopback_override_is_allowed_but_unauthenticated() {
        let verifier = dev_loopback().unwrap();
        assert!(!verifier.provider_identity_verified());
        // Nothing is listening in the test process, so the call fails at
        // connect time — the point is that it was attempted at all, and that
        // the transport is the loopback HTTP one.
        assert_eq!(verifier.endpoint(), "http://127.0.0.1:8546");
        assert!(verifier.health().is_err());
    }

    #[test]
    fn verifier_cannot_broadcast_even_against_a_pinned_provider() {
        let dir = tempfile::tempdir().unwrap();
        let server = FakeRpcSocket::bind(dir.path().join("verifier.sock"));
        let verifier = pinned(&server).unwrap();
        for method in [
            "eth_sendRawTransaction",
            "eth_sendTransaction",
            "eth_signTransaction",
            "personal_sendTransaction",
            "eth_sign",
        ] {
            let err = verifier.rpc_call(method, json!([])).unwrap_err();
            assert!(
                err.to_string()
                    .contains("RPC method not allowed by read-only verifier"),
                "method {method} was not rejected"
            );
        }
        assert!(
            !server
                .requested_methods()
                .iter()
                .any(|m| m.contains("Raw") || m.contains("Transaction")),
            "a rejected broadcast method reached the provider"
        );
    }

    #[test]
    fn provider_pin_must_exist_on_disk_before_verifying() {
        let dir = tempfile::tempdir().unwrap();
        let pin = PinnedChainProvider::unix_socket(
            dir.path().join("absent.sock"),
            Some(0),
        )
        .unwrap();
        let resolved = resolve(None, Some(&pin)).unwrap();
        // Resolution succeeds (the pin is configured); construction fails
        // closed because the socket the pin names does not exist.
        let err = BaseUsdcVerifier::from_resolved(&resolved, 2).unwrap_err();
        assert!(err.to_string().contains("unusable"));
    }

    #[test]
    fn socket_path_rejects_a_loopback_pin() {
        let pin = PinnedChainProvider::parse("http://127.0.0.1:8546", None).unwrap();
        let err = pin.socket_path().unwrap_err();
        assert!(err
            .to_string()
            .contains("pinned provider is not a unix socket"));
    }
}
