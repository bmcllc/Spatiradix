//! Ponte financeira entre a emissão mainnet (`mycelium-mint`, 1 MYC = 8 USDC)
//! e o banco soberano (`mycelium-bank`).
//!
//! Converte recibos verificados (`MintReceipt`) de 8 casas decimais (`COIN = 1e8`)
//! para micro-unidades do banco (`1e-6`), credita `Asset::Myc` na conta do
//! beneficiário e registra um lançamento `Entry::Credit` hash-encadeado no
//! `SovereignLedger` com guarda anti-replay por `nullifier`.

use crate::accounts::Portfolio;
use crate::assets::Asset;
use crate::error::BankError;
use crate::ledger::{Entry, SovereignLedger};
use mycelium_mint::{MintReceipt, MonetaryPolicy};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufRead, BufReader};

/// Divisor de conversão entre unidades base do `mycelium-mint` (1e8) e micros do `mycelium-bank` (1e6).
pub const MYC_TO_BANK_MICRO_DIVISOR: u64 = 100;

/// Resumo auditável da liquidação de um `MintReceipt` no `mycelium-bank`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintSettlementRecord {
    pub account_id: String,
    pub myc_micros: i64,
    pub reference_usdc_micros: i64,
    pub usdc_per_myc: u64,
    pub chronicle_hex: String,
    pub nullifier_hex: String,
    pub ledger_record_hash: String,
}

/// Converte unidades base do `mycelium-mint` (1e8) para micros do `mycelium-bank` (1e6).
pub fn myc_base_to_bank_micros(myc_base_units: u64) -> Result<i64, BankError> {
    let micros = myc_base_units / MYC_TO_BANK_MICRO_DIVISOR;
    i64::try_from(micros)
        .map_err(|_| BankError::Invalid("valor de emissão excede i64 micros".into()))
}

/// Verifica se o `ref_id` já foi liquidado anteriormente no `bank-ledger.jsonl`.
fn ref_id_exists(ledger: &SovereignLedger, ref_id: &str) -> Result<bool, BankError> {
    if !ledger.ledger_path().exists() {
        return Ok(false);
    }
    let f = File::open(ledger.ledger_path())?;
    for line in BufReader::new(f).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let rec: crate::ledger::Record = serde_json::from_str(&line)?;
        if let Entry::Credit {
            ref_id: existing, ..
        } = rec.entry
        {
            if existing == ref_id {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Liquida um `MintReceipt` da mainnet no `Portfolio` e no `SovereignLedger`.
///
/// Rejeita recibos cujo compromisso de Pedersen não abra ou cujo `nullifier`
/// já tenha sido creditado no razão bancário.
pub fn settle_mint_receipt(
    receipt: &MintReceipt,
    policy: &MonetaryPolicy,
    portfolio: &mut Portfolio,
    ledger: &SovereignLedger,
    now_unix: u64,
) -> Result<MintSettlementRecord, BankError> {
    receipt
        .verify_commitment()
        .map_err(|e| BankError::Invalid(format!("mint commitment inválido: {e}")))?;

    let nullifier_hex = hex::encode(receipt.nullifier);
    let ref_id = format!("mint:{nullifier_hex}");
    if ref_id_exists(ledger, &ref_id)? {
        return Err(BankError::Conflict(format!(
            "emissão já liquidada no banco ({ref_id})"
        )));
    }

    let myc_micros = myc_base_to_bank_micros(receipt.amount)?;
    if myc_micros <= 0 {
        return Err(BankError::Invalid(
            "valor convertido para micros é zero".into(),
        ));
    }

    let ref_usdc_base = policy.myc_to_usdc(receipt.amount);
    let reference_usdc_micros = i64::try_from(ref_usdc_base / MYC_TO_BANK_MICRO_DIVISOR as u128)
        .map_err(|_| BankError::Invalid("equivalente USDC excede i64 micros".into()))?;

    let account_id = receipt.beneficiary.to_string();
    if !portfolio.accounts.contains_key(&account_id) {
        portfolio.open_account(&account_id, &account_id, now_unix)?;
    }
    let account = portfolio
        .accounts
        .get_mut(&account_id)
        .ok_or_else(|| BankError::NotFound(account_id.clone()))?;
    account.credit(Asset::Myc, myc_micros)?;

    let rec = ledger.append(Entry::Credit {
        account_id: account_id.clone(),
        asset: Asset::Myc.symbol(),
        micros: myc_micros,
        ref_id,
        at: now_unix,
    })?;

    Ok(MintSettlementRecord {
        account_id,
        myc_micros,
        reference_usdc_micros,
        usdc_per_myc: policy.usdc_per_myc,
        chronicle_hex: hex::encode(receipt.chronicle_hash),
        nullifier_hex,
        ledger_record_hash: rec.record_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use mycelium_core::{ContentId, NodeId};
    use mycelium_mint::{MainnetMintEngine, SporocarpAttestation, WorkClaim, COIN};
    use mycelium_nutrients::TxKind;
    use std::collections::HashMap;

    #[test]
    fn settles_mint_receipt_into_bank_with_1_myc_equals_8_usdc_and_blocks_replay() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = SovereignLedger::open(dir.path()).unwrap();
        let mut portfolio = Portfolio::default();

        let val_sk = SigningKey::from_bytes(&[7u8; 32]);
        let val_pk = val_sk.verifying_key().to_bytes();
        let mut sporocarps = HashMap::new();
        sporocarps.insert(NodeId::derive(&val_pk), val_pk);

        let mut policy = MonetaryPolicy::mainnet();
        policy.initial_epoch_budget = 10 * COIN; // 10 MYC = 80 USDC
        policy.max_node_share_bps = 10_000;
        policy.min_hashcash_bits = 4;

        let mut engine =
            MainnetMintEngine::genesis("mycelium-bank-test", b"seed", policy.clone(), sporocarps, 1)
                .unwrap();

        let producer = NodeId::derive(b"miner-bank-1");
        let client = SigningKey::from_bytes(&[9u8; 32]);
        let claim = WorkClaim::build_signed(
            "mycelium-bank-test",
            0,
            producer,
            &client,
            ContentId::of(b"work-bank-1"),
            TxKind::Compute,
            10,
            5_000,
            5_000,
            4,
        );
        let root = engine.compute_batch_root(0, &[claim.clone()]);
        let att = SporocarpAttestation::sign("mycelium-bank-test", 0, root, &val_sk);
        let receipts = engine.settle_epoch(&[claim], &[att]).unwrap();

        let settled =
            settle_mint_receipt(&receipts[0], &policy, &mut portfolio, &ledger, 1_700_000_000)
                .unwrap();
        assert_eq!(settled.myc_micros, 10_000_000); // 10.000000 MYC
        assert_eq!(settled.reference_usdc_micros, 80_000_000); // 80.000000 USDC (1 MYC = 8 USDC)
        assert_eq!(settled.usdc_per_myc, 8);
        assert_eq!(
            portfolio.accounts[&settled.account_id].balance(Asset::Myc),
            10_000_000
        );

        // Replay do mesmo recibo deve ser bloqueado no bank-ledger.jsonl.
        let dup = settle_mint_receipt(&receipts[0], &policy, &mut portfolio, &ledger, 1_700_000_001);
        assert!(matches!(dup, Err(BankError::Conflict(_))));
    }
}
