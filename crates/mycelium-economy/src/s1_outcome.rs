//! Fail-closed verification of realized S1 outcomes on Base.
//!
//! A modeled S1 edge is not revenue. This verifier only emits a verified
//! ExternalValueReceipt after reconciling an S1 receipt against canonical Base
//! transaction/block/log evidence through the local read-only RPC.

use crate::{
    autonomy::{ExternalValueClass, ExternalValueReceipt},
    base_usdc::{
        normalize_address, BaseUsdcVerification, BaseUsdcVerifier, BASE_CHAIN_ID,
        BASE_USDC, ERC20_TRANSFER_TOPIC,
    },
    boundary::{BoundaryEvidence, RealAsset},
    chain_provider::{
        resolve, PinnedChainProvider, ResolvedChainProvider,
    },
    EconomyError, Result, SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::Keccak256;
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S1OutcomePolicy {
    pub schema_version: u32,
    pub executor: String,
    pub min_confirmations: u64,
    pub created_at_unix: u64,
    /// Chain data source for the reconciliation, pinned out-of-band. `None` on
    /// a policy written before pinning existed: it still loads, but
    /// reconciliation refuses until a provider is pinned.
    #[serde(default)]
    pub chain_provider: Option<PinnedChainProvider>,
}

#[derive(Debug, Clone, Deserialize)]
struct S1ReconciledReceipt {
    chain_id: u64,
    transaction_hash: String,
    block_number: u64,
    block_hash: String,
    intent_hash: String,
    sponsor: String,
    beneficiary: String,
    beneficiary_profit_usdc: u64,
    gross_profit_usdc: u64,
    sponsor_payment_usdc: u64,
    verdict: String,
    receipt_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedS1Outcome {
    pub transaction_hash: String,
    pub block_number: u64,
    pub block_hash: String,
    pub confirmations: u64,
    pub executor: String,
    pub sponsor: String,
    pub beneficiary: String,
    pub beneficiary_profit_usdc_raw: u64,
    pub s1_receipt_hash: String,
    /// Endpoint the chain evidence actually came from.
    pub chain_provider: String,
    /// True when that endpoint's identity was enforced by the kernel.
    pub provider_identity_verified: bool,
    /// The boundary evidence for the leg that actually moved USDC into the
    /// beneficiary: the executor (external to our controlled set) paying the
    /// beneficiary (controlled) inside the reconciled transaction. Recorded as
    /// evidence and re-derived by the boundary on read, never as a domain.
    pub boundary_evidence: BoundaryEvidence,
    /// The same transfer, re-read through the pinned verifier, in the shape
    /// `BoundaryCrossing::with_verified_proof` requires: same chain, token,
    /// amount, recipient, transaction and block.
    pub payment_proof: BaseUsdcVerification,
    pub external_value: ExternalValueReceipt,
}

pub fn policy_path(root: impl AsRef<Path>) -> PathBuf {
    root.as_ref().join("s1-outcome-policy.json")
}

pub fn init_policy(
    root: impl AsRef<Path>,
    executor: &str,
    min_confirmations: u64,
) -> Result<S1OutcomePolicy> {
    init_policy_with_provider(root, executor, min_confirmations, None)
}

/// Create-once policy that also pins the chain provider, so the source of
/// truth for reconciliation is fixed when the executor is deployed and cannot
/// be moved by a later command line.
pub fn init_policy_with_provider(
    root: impl AsRef<Path>,
    executor: &str,
    min_confirmations: u64,
    chain_provider: Option<&PinnedChainProvider>,
) -> Result<S1OutcomePolicy> {
    if min_confirmations == 0 {
        return Err(EconomyError::Invalid(
            "S1 outcome min_confirmations must be >= 1".into(),
        ));
    }
    if let Some(provider) = chain_provider {
        provider.validate_policy_pin()?;
    }
    let executor = normalize_address(executor)?;
    let path = policy_path(&root);
    crate::durability::ensure_private_dir(root.as_ref())?;
    if path.exists() {
        return Err(EconomyError::Conflict(
            "S1 outcome policy already exists".into(),
        ));
    }
    let policy = S1OutcomePolicy {
        schema_version: SCHEMA_VERSION,
        executor,
        min_confirmations,
        created_at_unix: crate::now_unix(),
        chain_provider: chain_provider.cloned(),
    };
    // Atomic write at 0600: the policy names the executor address and the
    // pinned source of truth, and a create-once policy must never be observed
    // half-written.
    let mut payload = serde_json::to_vec_pretty(&policy)?;
    payload.push(b'\n');
    crate::durability::write_private_atomic(&path, &payload)?;
    Ok(policy)
}

pub fn load_policy(root: impl AsRef<Path>) -> Result<S1OutcomePolicy> {
    let path = policy_path(root);
    if !path.exists() {
        return Err(EconomyError::NotFound(
            "S1 outcome policy; configure the deployed executor first".into(),
        ));
    }
    let policy: S1OutcomePolicy = serde_json::from_slice(&fs::read(path)?)?;
    if policy.schema_version != SCHEMA_VERSION {
        return Err(EconomyError::Invalid(
            "unsupported S1 outcome policy schema".into(),
        ));
    }
    if let Some(provider) = &policy.chain_provider {
        provider.validate_policy_pin()?;
    }
    Ok(policy)
}

/// Pins the chain provider on an existing S1 outcome policy, for an operator
/// whose policy predates provider pinning.
pub fn pin_policy_provider(
    root: impl AsRef<Path>,
    provider: &PinnedChainProvider,
) -> Result<S1OutcomePolicy> {
    provider.validate_policy_pin()?;
    let path = policy_path(&root);
    let mut policy = load_policy(root)?;
    policy.chain_provider = Some(provider.clone());
    let mut payload = serde_json::to_vec_pretty(&policy)?;
    payload.push(b'\n');
    crate::durability::write_private_atomic(&path, &payload)?;
    Ok(policy)
}

/// Chain provider for S1 reconciliation, resolved exactly like the payment
/// path: dev-only environment override first, then the pin carried by the
/// policy, otherwise fail closed.
pub fn resolve_chain_provider(
    policy: &S1OutcomePolicy,
) -> Result<ResolvedChainProvider> {
    let dev = std::env::var(crate::chain_provider::DEV_PROVIDER_ENV).ok();
    resolve(dev.as_deref(), policy.chain_provider.as_ref())
}

/// Verifies a reconciled receipt against the provider pinned in the policy.
/// The chain endpoint is never an argument here: the caller cannot choose the
/// source of truth.
pub fn verify_reconciled_receipt_pinned(
    receipt_path: impl AsRef<Path>,
    agent_id: &str,
    opportunity_id: &str,
    policy: &S1OutcomePolicy,
) -> Result<VerifiedS1Outcome> {
    let provider = resolve_chain_provider(policy)?;
    verify_reconciled_receipt_with_provider(
        receipt_path,
        agent_id,
        opportunity_id,
        &provider,
        policy,
    )
}

/// Backwards-compatible entry point.
///
/// `rpc_url` is no longer authoritative. It is accepted only when it matches
/// the provider pinned in the policy, so an existing caller keeps working and
/// an argv-supplied URL can never redirect reconciliation. Prefer
/// [`verify_reconciled_receipt_pinned`].
pub fn verify_reconciled_receipt(
    receipt_path: impl AsRef<Path>,
    agent_id: &str,
    opportunity_id: &str,
    rpc_url: &str,
    policy: &S1OutcomePolicy,
) -> Result<VerifiedS1Outcome> {
    let provider = resolve_chain_provider(policy)?;
    if !rpc_url.eq_ignore_ascii_case(provider.provider.endpoint()) {
        return Err(EconomyError::Invalid(format!(
            "endpoint argument does not match the provider pinned in the S1 outcome \
             policy: pinned {}, given {rpc_url}",
            provider.provider.endpoint()
        )));
    }
    verify_reconciled_receipt_with_provider(
        receipt_path,
        agent_id,
        opportunity_id,
        &provider,
        policy,
    )
}

fn verify_reconciled_receipt_with_provider(
    receipt_path: impl AsRef<Path>,
    agent_id: &str,
    opportunity_id: &str,
    provider: &ResolvedChainProvider,
    policy: &S1OutcomePolicy,
) -> Result<VerifiedS1Outcome> {
    if agent_id.trim().is_empty() || opportunity_id.trim().is_empty() {
        return Err(EconomyError::Invalid(
            "S1 outcome requires agent_id and opportunity_id".into(),
        ));
    }

    let bytes = fs::read(receipt_path)?;
    let full_value: Value = serde_json::from_slice(&bytes)?;
    verify_receipt_hash(&full_value)?;
    let receipt: S1ReconciledReceipt = serde_json::from_value(full_value)?;

    validate_receipt_shape(&receipt)?;

    let executor = normalize_address(&policy.executor)?;
    let sponsor = normalize_address(&receipt.sponsor)?;
    let beneficiary = normalize_address(&receipt.beneficiary)?;

    // The endpoint comes from the pin, never from the caller. The chain-id
    // comparison below is unchanged and still runs against whatever answered.
    let rpc = BaseUsdcVerifier::from_resolved(
        provider,
        policy.min_confirmations,
    )?;
    let chain_id = parse_hex_u64(
        rpc.rpc_call("eth_chainId", json!([]))?
            .as_str()
            .ok_or_else(|| EconomyError::Invalid(
                "eth_chainId did not return hex".into(),
            ))?,
    )?;
    if chain_id != BASE_CHAIN_ID {
        return Err(EconomyError::Invalid(
            "S1 outcome RPC is not Base mainnet".into(),
        ));
    }

    let onchain_receipt = rpc.rpc_call(
        "eth_getTransactionReceipt",
        json!([receipt.transaction_hash]),
    )?;
    if onchain_receipt.is_null() {
        return Err(EconomyError::Invalid(
            "S1 outcome transaction not found on Base".into(),
        ));
    }
    if hex_field_u64(&onchain_receipt, "status")? != 1 {
        return Err(EconomyError::Invalid(
            "S1 outcome transaction reverted".into(),
        ));
    }
    if hex_field_u64(&onchain_receipt, "blockNumber")? != receipt.block_number {
        return Err(EconomyError::Invalid(
            "S1 receipt block number does not match Base".into(),
        ));
    }
    let onchain_block_hash = string_field(&onchain_receipt, "blockHash")?;
    if !eq_hex(onchain_block_hash, &receipt.block_hash) {
        return Err(EconomyError::Invalid(
            "S1 receipt block hash does not match Base".into(),
        ));
    }
    let onchain_tx_hash = string_field(&onchain_receipt, "transactionHash")?;
    if !eq_hex(onchain_tx_hash, &receipt.transaction_hash) {
        return Err(EconomyError::Invalid(
            "S1 receipt transaction hash mismatch".into(),
        ));
    }

    let tx = rpc.rpc_call(
        "eth_getTransactionByHash",
        json!([receipt.transaction_hash]),
    )?;
    if tx.is_null() {
        return Err(EconomyError::Invalid(
            "S1 outcome transaction body unavailable".into(),
        ));
    }
    let tx_to = normalize_address(string_field(&tx, "to")?)?;
    let tx_from = normalize_address(string_field(&tx, "from")?)?;
    if tx_to != executor {
        return Err(EconomyError::Invalid(
            "S1 outcome transaction target is not configured executor".into(),
        ));
    }
    if tx_from != sponsor {
        return Err(EconomyError::Invalid(
            "S1 outcome transaction sender is not reconciled sponsor".into(),
        ));
    }
    let tx_block_hash = string_field(&tx, "blockHash")?;
    if !eq_hex(tx_block_hash, &receipt.block_hash) {
        return Err(EconomyError::Invalid(
            "S1 transaction is not in reconciled block".into(),
        ));
    }

    let block = rpc.rpc_call(
        "eth_getBlockByNumber",
        json!([format!("0x{:x}", receipt.block_number), false]),
    )?;
    if block.is_null() || !eq_hex(string_field(&block, "hash")?, &receipt.block_hash) {
        return Err(EconomyError::Invalid(
            "S1 reconciled block is not canonical".into(),
        ));
    }
    let block_timestamp = hex_field_u64(&block, "timestamp")?;
    let latest = parse_hex_u64(
        rpc.rpc_call("eth_blockNumber", json!([]))?
            .as_str()
            .ok_or_else(|| EconomyError::Invalid(
                "eth_blockNumber did not return hex".into(),
            ))?,
    )?;
    let confirmations = latest
        .saturating_sub(receipt.block_number)
        .saturating_add(1);
    if confirmations < policy.min_confirmations {
        return Err(EconomyError::Invalid(format!(
            "S1 outcome has {confirmations} confirmations; need {}",
            policy.min_confirmations
        )));
    }

    verify_shared_execution_event(
        &onchain_receipt,
        &executor,
        &receipt.intent_hash,
        &sponsor,
        &beneficiary,
        receipt.sponsor_payment_usdc,
        receipt.beneficiary_profit_usdc,
    )?;
    verify_beneficiary_usdc_transfer(
        &onchain_receipt,
        &executor,
        &beneficiary,
        receipt.beneficiary_profit_usdc,
    )?;

    let external_value = ExternalValueReceipt {
        schema_version: SCHEMA_VERSION,
        // Carries both hashes so the S1 receipt stays citable from the ledger
        // without adding a field to a hash-chained struct. Only `source_id`
        // and `proof_hash` are free-form; the deduplication key stays unique
        // per (transaction, S1 receipt) pair.
        source_id: format!(
            "s1-base:{}:{}",
            receipt.transaction_hash.to_ascii_lowercase(),
            receipt.receipt_hash.to_ascii_lowercase()
        ),
        agent_id: agent_id.to_string(),
        opportunity_id: opportunity_id.to_string(),
        value_class: ExternalValueClass::ExternalTradingPnl,
        network: "base".into(),
        asset: "USDC".into(),
        // Conservative accounting: only the amount actually paid to the S1
        // beneficiary is booked. Sponsor/internal redistribution is excluded.
        gross_inflow_musd_micros: receipt.beneficiary_profit_usdc,
        external_cost_musd_micros: 0,
        net_external_value_musd_micros: receipt.beneficiary_profit_usdc as i64,
        // The Base transaction, not the S1 receipt hash. This is the P3 wiring
        // decision: `with_verified_proof` requires `proof_hash == crossing.tx_hash`,
        // and an S1 receipt hash names no transaction a provider could be asked
        // about, so a receipt citing one can never be re-derived and never
        // counts. The value written into NEW records changes, so new
        // record_hashes differ from what the previous code produced; nothing
        // already on disk is rewritten, and an S1 receipt written before this
        // change still parses and is reported as unattested with the reason
        // spelled out.
        proof_hash: receipt.transaction_hash.to_ascii_lowercase(),
        proof_verified: true,
        realized_at_unix: block_timestamp,
        verifier_id: "s1-base-reconcile-v1".into(),
    };

    // The same transfer, through the pinned verifier, so the caller can bind a
    // proof to a derived crossing. This is the same read the reconciler already
    // performed against the raw receipt; it is re-done through the typed path so
    // the proof carries the shape `with_verified_proof` checks.
    let payment_proof = rpc.verify_transfer(
        &receipt.transaction_hash,
        &beneficiary,
        receipt.beneficiary_profit_usdc,
    )?;

    let boundary_evidence = BoundaryEvidence {
        chain_id: BASE_CHAIN_ID,
        asset: RealAsset::base_usdc(),
        from_address: executor.clone(),
        to_address: beneficiary.clone(),
        amount_raw: receipt.beneficiary_profit_usdc,
        tx_hash: receipt.transaction_hash.to_ascii_lowercase(),
        block_hash: receipt.block_hash.to_ascii_lowercase(),
    };

    Ok(VerifiedS1Outcome {
        transaction_hash: receipt.transaction_hash.to_ascii_lowercase(),
        block_number: receipt.block_number,
        block_hash: receipt.block_hash.to_ascii_lowercase(),
        confirmations,
        executor,
        sponsor,
        beneficiary,
        beneficiary_profit_usdc_raw: receipt.beneficiary_profit_usdc,
        s1_receipt_hash: receipt.receipt_hash.to_ascii_lowercase(),
        chain_provider: provider.provider.endpoint().to_string(),
        provider_identity_verified: provider.identity_kernel_enforced(),
        boundary_evidence,
        payment_proof,
        external_value,
    })
}

fn validate_receipt_shape(r: &S1ReconciledReceipt) -> Result<()> {
    if r.chain_id != BASE_CHAIN_ID {
        return Err(EconomyError::Invalid(
            "S1 reconciled receipt chain_id must be 8453".into(),
        ));
    }
    if r.verdict != "RECONCILED" {
        return Err(EconomyError::Invalid(
            "S1 receipt verdict must be RECONCILED".into(),
        ));
    }
    validate_hash32("transaction_hash", &r.transaction_hash)?;
    validate_hash32("block_hash", &r.block_hash)?;
    validate_hash32("intent_hash", &r.intent_hash)?;
    validate_hash32("receipt_hash", &r.receipt_hash)?;
    if r.beneficiary_profit_usdc == 0 {
        return Err(EconomyError::Invalid(
            "S1 beneficiary profit must be > 0".into(),
        ));
    }
    if r.beneficiary_profit_usdc > i64::MAX as u64 {
        return Err(EconomyError::Invalid(
            "S1 beneficiary profit exceeds signed 64-bit micros ABI".into(),
        ));
    }
    if r.gross_profit_usdc
        != r
            .sponsor_payment_usdc
            .saturating_add(r.beneficiary_profit_usdc)
    {
        return Err(EconomyError::Invalid(
            "S1 gross profit does not equal sponsor payment + beneficiary profit".into(),
        ));
    }
    Ok(())
}

fn verify_receipt_hash(value: &Value) -> Result<()> {
    let mut canonical = value.clone();
    let object = canonical
        .as_object_mut()
        .ok_or_else(|| EconomyError::Invalid(
            "S1 receipt must be a JSON object".into(),
        ))?;
    let expected = object
        .remove("receipt_hash")
        .and_then(|v| v.as_str().map(str::to_string))
        .ok_or_else(|| EconomyError::Invalid(
            "S1 receipt missing receipt_hash".into(),
        ))?;
    validate_hash32("receipt_hash", &expected)?;

    let compact = serde_json::to_vec(&canonical)?;
    let digest = Sha256::digest(&compact);
    let actual = format!("0x{}", hex::encode(digest));
    if !eq_hex(&actual, &expected) {
        return Err(EconomyError::Invalid(
            "S1 receipt_hash is not canonical".into(),
        ));
    }
    Ok(())
}

fn verify_shared_execution_event(
    receipt: &Value,
    executor: &str,
    intent_hash: &str,
    sponsor: &str,
    beneficiary: &str,
    sponsor_payment: u64,
    beneficiary_profit: u64,
) -> Result<()> {
    let topic0 = keccak_topic(
        b"SharedExecution(bytes32,address,address,uint256,uint256,uint256)",
    );
    let logs = receipt
        .get("logs")
        .and_then(Value::as_array)
        .ok_or_else(|| EconomyError::Invalid(
            "S1 Base receipt missing logs".into(),
        ))?;

    let mut matched = 0u64;
    for log in logs {
        if !eq_hex(
            log.get("address").and_then(Value::as_str).unwrap_or_default(),
            executor,
        ) {
            continue;
        }
        let topics = match log.get("topics").and_then(Value::as_array) {
            Some(v) if v.len() == 4 => v,
            _ => continue,
        };
        if !eq_hex(topics[0].as_str().unwrap_or_default(), &topic0)
            || !eq_hex(topics[1].as_str().unwrap_or_default(), intent_hash)
            || topic_address(topics[2].as_str().unwrap_or_default())? != sponsor
            || topic_address(topics[3].as_str().unwrap_or_default())? != beneficiary
        {
            continue;
        }
        let data = log.get("data").and_then(Value::as_str).unwrap_or_default();
        let words = data_words3(data)?;
        if words[1] != sponsor_payment || words[2] != beneficiary_profit {
            return Err(EconomyError::Invalid(
                "SharedExecution payment data mismatch".into(),
            ));
        }
        matched += 1;
    }
    if matched != 1 {
        return Err(EconomyError::Invalid(
            "expected exactly one matching SharedExecution event".into(),
        ));
    }
    Ok(())
}

fn verify_beneficiary_usdc_transfer(
    receipt: &Value,
    executor: &str,
    beneficiary: &str,
    beneficiary_profit: u64,
) -> Result<()> {
    let logs = receipt
        .get("logs")
        .and_then(Value::as_array)
        .ok_or_else(|| EconomyError::Invalid(
            "S1 Base receipt missing logs".into(),
        ))?;
    let mut matched = 0u64;
    for log in logs {
        if !eq_hex(
            log.get("address").and_then(Value::as_str).unwrap_or_default(),
            BASE_USDC,
        ) {
            continue;
        }
        let topics = match log.get("topics").and_then(Value::as_array) {
            Some(v) if v.len() == 3 => v,
            _ => continue,
        };
        if !eq_hex(topics[0].as_str().unwrap_or_default(), ERC20_TRANSFER_TOPIC) {
            continue;
        }
        if topic_address(topics[1].as_str().unwrap_or_default())? != executor
            || topic_address(topics[2].as_str().unwrap_or_default())? != beneficiary
        {
            continue;
        }
        let amount = parse_hex_u128(
            log.get("data").and_then(Value::as_str).unwrap_or("0x0"),
        )?;
        if amount == beneficiary_profit as u128 {
            matched += 1;
        }
    }
    if matched != 1 {
        return Err(EconomyError::Invalid(
            "beneficiary USDC transfer from S1 executor not proven exactly once".into(),
        ));
    }
    Ok(())
}

fn keccak_topic(input: &[u8]) -> String {
    let mut hasher = Keccak256::new();
    sha3::Digest::update(&mut hasher, input);
    format!("0x{}", hex::encode(hasher.finalize()))
}

fn data_words3(data: &str) -> Result<[u64; 3]> {
    let raw = data.strip_prefix("0x").unwrap_or(data);
    if raw.len() != 64 * 3 || !raw.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(EconomyError::Invalid(
            "SharedExecution data must contain exactly three ABI words".into(),
        ));
    }
    let mut out = [0u64; 3];
    for (i, item) in out.iter_mut().enumerate() {
        let word = &raw[i * 64..(i + 1) * 64];
        let value = u128::from_str_radix(word, 16)
            .map_err(|_| EconomyError::Invalid(
                "invalid SharedExecution ABI word".into(),
            ))?;
        if value > u64::MAX as u128 {
            return Err(EconomyError::Invalid(
                "SharedExecution value exceeds u64".into(),
            ));
        }
        *item = value as u64;
    }
    Ok(out)
}

fn topic_address(topic: &str) -> Result<String> {
    let raw = topic.strip_prefix("0x").unwrap_or(topic);
    if raw.len() != 64 || !raw.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(EconomyError::Invalid(
            "event address topic must be 32 bytes".into(),
        ));
    }
    normalize_address(&format!("0x{}", &raw[24..]))
}

fn string_field<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| EconomyError::Invalid(format!(
            "RPC object missing string field {key}"
        )))
}

fn hex_field_u64(v: &Value, key: &str) -> Result<u64> {
    parse_hex_u64(string_field(v, key)?)
}

fn parse_hex_u64(s: &str) -> Result<u64> {
    let raw = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(if raw.is_empty() { "0" } else { raw }, 16)
        .map_err(|_| EconomyError::Invalid(format!("invalid hex u64: {s}")))
}

fn parse_hex_u128(s: &str) -> Result<u128> {
    let raw = s.strip_prefix("0x").unwrap_or(s);
    u128::from_str_radix(if raw.is_empty() { "0" } else { raw }, 16)
        .map_err(|_| EconomyError::Invalid(format!("invalid hex u128: {s}")))
}

fn validate_hash32(name: &str, value: &str) -> Result<()> {
    // The rule lives once, in the Base adapter; this keeps the local name used
    // throughout this module without a second copy of the check.
    crate::base_usdc::validate_hash32(name, value)
}

fn eq_hex(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn canonical_fixture() -> Value {
        let mut v = json!({
            "chain_id": 8453,
            "transaction_hash": format!("0x{}", "11".repeat(32)),
            "block_number": 123,
            "block_hash": format!("0x{}", "22".repeat(32)),
            "intent_hash": format!("0x{}", "33".repeat(32)),
            "sponsor": "0x1111111111111111111111111111111111111111",
            "beneficiary": "0x2222222222222222222222222222222222222222",
            "beneficiary_profit_usdc": 5000000,
            "gross_profit_usdc": 6000000,
            "sponsor_payment_usdc": 1000000,
            "verdict": "RECONCILED"
        });
        let digest = Sha256::digest(serde_json::to_vec(&v).unwrap());
        v.as_object_mut().unwrap().insert(
            "receipt_hash".into(),
            Value::String(format!("0x{}", hex::encode(digest))),
        );
        v
    }

    #[test]
    fn canonical_receipt_hash_is_verified() {
        let v = canonical_fixture();
        verify_receipt_hash(&v).unwrap();
        let parsed: S1ReconciledReceipt = serde_json::from_value(v).unwrap();
        validate_receipt_shape(&parsed).unwrap();
    }

    #[test]
    fn tampered_receipt_hash_is_rejected() {
        let mut v = canonical_fixture();
        v["beneficiary_profit_usdc"] = json!(5000001);
        assert!(verify_receipt_hash(&v).is_err());
    }

    #[test]
    fn gross_profit_conservation_is_required() {
        let mut v = canonical_fixture();
        // Recompute hash so this test reaches economic conservation.
        v.as_object_mut().unwrap().remove("receipt_hash");
        v["gross_profit_usdc"] = json!(9000000);
        let digest = Sha256::digest(serde_json::to_vec(&v).unwrap());
        v.as_object_mut().unwrap().insert(
            "receipt_hash".into(),
            Value::String(format!("0x{}", hex::encode(digest))),
        );
        verify_receipt_hash(&v).unwrap();
        let parsed: S1ReconciledReceipt = serde_json::from_value(v).unwrap();
        assert!(validate_receipt_shape(&parsed).is_err());
    }

    #[test]
    fn outcome_policy_is_create_once() {
        let dir = tempdir().unwrap();
        let executor = "0x1234567890abcdef1234567890abcdef12345678";
        let p = init_policy(dir.path(), executor, 2).unwrap();
        assert_eq!(p.executor, executor);
        assert!(init_policy(dir.path(), executor, 2).is_err());
        assert_eq!(load_policy(dir.path()).unwrap().executor, executor);
    }

    #[test]
    fn outcome_policy_without_a_provider_fails_closed() {
        let dir = tempdir().unwrap();
        let executor = "0x1234567890abcdef1234567890abcdef12345678";
        let policy = init_policy(dir.path(), executor, 2).unwrap();
        assert!(policy.chain_provider.is_none());
        // An unpinned policy still loads; reconciliation refuses.
        let err = resolve_chain_provider(&load_policy(dir.path()).unwrap())
            .unwrap_err();
        assert!(matches!(err, EconomyError::ProviderUnpinned(_)));
    }

    #[test]
    fn outcome_policy_carries_the_pinned_provider() {
        let dir = tempdir().unwrap();
        let executor = "0x1234567890abcdef1234567890abcdef12345678";
        let pin =
            PinnedChainProvider::unix_socket("/run/mycelium-verifier.sock", Some(0))
                .unwrap();
        init_policy_with_provider(
            dir.path(),
            executor,
            2,
            Some(&pin),
        )
        .unwrap();
        let resolved =
            resolve_chain_provider(&load_policy(dir.path()).unwrap()).unwrap();
        assert_eq!(
            resolved.provider.endpoint(),
            "unix:///run/mycelium-verifier.sock"
        );
        assert!(resolved.identity_kernel_enforced());
        assert!(!resolved.is_dev_override());
        // A loopback URL cannot be pinned here either.
        assert!(init_policy_with_provider(
            dir.path(),
            executor,
            2,
            Some(&PinnedChainProvider::parse("http://127.0.0.1:8546", None).unwrap()),
        )
        .is_err());
    }

    #[test]
    fn endpoint_argument_cannot_redirect_a_pinned_reconciliation() {
        let dir = tempdir().unwrap();
        let executor = "0x1234567890abcdef1234567890abcdef12345678";
        let pin =
            PinnedChainProvider::unix_socket("/run/mycelium-verifier.sock", Some(0))
                .unwrap();
        let policy =
            init_policy_with_provider(dir.path(), executor, 2, Some(&pin)).unwrap();
        let receipt = dir.path().join("receipt.json");
        std::fs::write(&receipt, canonical_fixture().to_string()).unwrap();
        // The argv endpoint is only accepted when it matches the pin.
        let err = verify_reconciled_receipt(
            &receipt,
            "agent-1",
            "opp-1",
            "http://127.0.0.1:8546",
            &policy,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("does not match the provider pinned"),
            "{err}"
        );
        // Matching the pin gets past the endpoint check and then fails on the
        // socket identity, which no argv can influence.
        let err = verify_reconciled_receipt(
            &receipt,
            "agent-1",
            "opp-1",
            "unix:///run/mycelium-verifier.sock",
            &policy,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unusable"), "{err}");
    }

    /// A provider that serves the reconciled transaction end to end: the
    /// canonical block, the receipt with the SharedExecution event, and the
    /// beneficiary USDC transfer. `FakeRpcSocket` binds a real owner-only Unix
    /// socket, so the kernel identity check runs rather than being stubbed.
    fn serving_socket(dir: &Path) -> crate::rpc_test_server::FakeRpcSocket {
        let receipt = canonical_fixture();
        let tx = receipt["transaction_hash"].as_str().unwrap().to_string();
        let block_hash = receipt["block_hash"].as_str().unwrap().to_string();
        let shared = serde_json::json!({
            "address": "0x1234567890abcdef1234567890abcdef12345678",
            "topics": [
                keccak_topic(b"SharedExecution(bytes32,address,address,uint256,uint256,uint256)"),
                format!("0x{}", "33".repeat(32)),
                format!("0x{:0>64}", "1111111111111111111111111111111111111111"),
                format!("0x{:0>64}", "2222222222222222222222222222222222222222"),
            ],
            "data": format!(
                "0x{:064x}{:064x}{:064x}",
                0u64, 1_000_000u64, 5_000_000u64
            ),
            "logIndex": "0x0",
        });
        let transfer = serde_json::json!({
            "address": BASE_USDC,
            "topics": [
                ERC20_TRANSFER_TOPIC,
                format!("0x{:0>64}", "1234567890abcdef1234567890abcdef12345678"),
                format!("0x{:0>64}", "2222222222222222222222222222222222222222"),
            ],
            "data": format!("0x{:064x}", 5_000_000u64),
            "logIndex": "0x1",
        });
        crate::rpc_test_server::FakeRpcSocket::with_responses(
            dir.join("verifier.sock"),
            vec![
                ("eth_chainId", serde_json::json!("0x2105")),
                ("eth_blockNumber", serde_json::json!("0x7e")),
                ("eth_getTransactionReceipt", serde_json::json!({
                    "status": "0x1",
                    "blockNumber": "0x7b",
                    "blockHash": block_hash,
                    "transactionHash": tx,
                    "from": "0x1111111111111111111111111111111111111111",
                    "to": "0x1234567890abcdef1234567890abcdef12345678",
                    "logs": [shared, transfer],
                })),
                ("eth_getTransactionByHash", serde_json::json!({
                    "blockHash": block_hash,
                    "transactionHash": tx,
                    "from": "0x1111111111111111111111111111111111111111",
                    "to": "0x1234567890abcdef1234567890abcdef12345678",
                })),
                ("eth_getBlockByNumber", serde_json::json!({
                    "hash": block_hash,
                    "timestamp": "0x6553f100",
                })),
            ],
        )
    }

    /// The P3 wiring decision, end to end: an S1 receipt produces a value receipt
    /// that cites the Base transaction, a boundary crossing the reader can
    /// re-derive, and a proof that binds to that crossing.
    ///
    /// Before this, the receipt cited the S1 receipt hash. No provider could be
    /// asked about it, so it could never satisfy `with_verified_proof` and no
    /// S1 value was re-derivable on read at all.
    #[test]
    fn a_reconciled_outcome_cites_the_base_transaction_and_carries_boundary_evidence()
    {
        let dir = tempdir().unwrap();
        let executor = "0x1234567890abcdef1234567890abcdef12345678";
        let receipt_path = dir.path().join("receipt.json");
        std::fs::write(&receipt_path, canonical_fixture().to_string()).unwrap();

        let socket = serving_socket(dir.path());
        let pin = PinnedChainProvider::unix_socket(socket.path(), Some(socket.uid()))
            .unwrap();
        let policy = init_policy_with_provider(
            dir.path(),
            executor,
            2,
            Some(&pin),
        )
        .unwrap();
        let verified =
            verify_reconciled_receipt_pinned(&receipt_path, "agent-1", "opp-1", &policy)
                .unwrap();

        // The cited proof is the transaction a provider can be asked about, and
        // the S1 receipt hash is still in the ledger through `source_id`.
        assert_eq!(verified.external_value.proof_hash, verified.transaction_hash);
        assert!(crate::base_usdc::validate_hash32(
            "proof_hash",
            &verified.external_value.proof_hash
        )
        .is_ok());
        assert!(verified
            .external_value
            .source_id
            .contains(&verified.s1_receipt_hash));
        // Conservative accounting is unchanged: only the beneficiary's payout.
        assert_eq!(
            verified.external_value.gross_inflow_musd_micros,
            5_000_000
        );
        assert_eq!(verified.external_value.external_cost_musd_micros, 0);
        assert_eq!(
            verified.external_value.net_external_value_musd_micros,
            5_000_000
        );

        // The evidence is the leg that actually moved the USDC, and it derives
        // into an external inflow against a registry that knows the beneficiary.
        let registry = crate::boundary::ControlledAddressRegistry::new()
            .with_address("0x2222222222222222222222222222222222222222")
            .unwrap();
        let crossing = crate::boundary::BoundaryCrossing::derive(
            &verified.boundary_evidence,
            &registry,
        )
        .unwrap();
        assert_eq!(crossing.kind(), crate::boundary::CrossingKind::ExternalToControlled);
        assert_eq!(crossing.to_address(), "0x2222222222222222222222222222222222222222");
        assert_eq!(crossing.amount_raw(), 5_000_000);
        // And the pinned proof binds to it, which is the check the old receipt
        // shape could never reach.
        let bound = crossing.clone().with_verified_proof(verified.payment_proof.clone());
        assert!(bound.is_ok(), "{bound:?}");
        assert!(bound.unwrap().proof().is_some());

        // With the executor also inside the controlled set the same bytes are an
        // internal transfer, so the receipt cannot be booked as external value.
        let both = crate::boundary::ControlledAddressRegistry::new()
            .with_address("0x2222222222222222222222222222222222222222")
            .unwrap()
            .with_address(executor)
            .unwrap();
        let internal = crate::boundary::BoundaryCrossing::derive(
            &verified.boundary_evidence,
            &both,
        )
        .unwrap();
        assert_eq!(internal.kind(), crate::boundary::CrossingKind::ControlledToControlled);
    }

    #[test]
    fn shared_execution_topic_matches_keccak_shape() {
        let topic = keccak_topic(
            b"SharedExecution(bytes32,address,address,uint256,uint256,uint256)",
        );
        assert_eq!(topic.len(), 66);
        assert!(topic.starts_with("0x"));
    }
}
