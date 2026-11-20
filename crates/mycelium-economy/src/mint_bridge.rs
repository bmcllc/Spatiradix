//! Ponte contábil entre `mycelium-mint` (emissão mainnet, 1 MYC = 8 USDC)
//! e `mycelium-economy`.
//!
//! Preserva estritamente o invariante fundamental do `mycelium-economy`:
//! trabalho interno e recompensas cunhadas em MYC são contabilizados sob
//! [`SyntheticAsset::SyntheticMyc`] com valor de referência em USDC, mas
//! **nunca incrementam `PaidDemand` externo**.

use crate::boundary::SyntheticAsset;
use crate::{EconomyError, Result};
use mycelium_mint::{MintReceipt, MonetaryPolicy};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Divisor de conversão entre unidades base do `mycelium-mint` (1e8) e micro-unidades (1e6).
pub const MINT_TO_MICRO_DIVISOR: u128 = 100;

/// Registro contábil imutável de um evento de emissão interna na mainnet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InternalMintEntry {
    pub epoch: u64,
    pub beneficiary: String,
    pub asset: SyntheticAsset,
    pub myc_base_units: u64,
    pub usdc_per_myc: u64,
    pub reference_usdc_micros: u128,
    pub chronicle_hex: String,
    pub nullifier_hex: String,
    /// Sempre zero: recompensas de emissão interna nunca contam como demanda paga externa.
    pub external_paid_demand_delta_micros: u64,
}

/// Acumulador contábil local-first de emissões da mainnet no `mycelium-economy`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InternalMintAccounting {
    pub total_minted_myc_base: u64,
    pub total_reference_usdc_micros: u128,
    /// Mantido explicitamente em 0 para auditar o invariante RV0 de demanda externa.
    pub external_paid_demand_micros: u64,
    pub seen_nullifiers: BTreeSet<String>,
    pub entries: Vec<InternalMintEntry>,
}

impl InternalMintAccounting {
    pub fn new() -> Self {
        Self::default()
    }

    /// Valida o compromisso de Pedersen, bloqueia replay e registra a emissão interna.
    pub fn record_mint_receipt(
        &mut self,
        receipt: &MintReceipt,
        policy: &MonetaryPolicy,
    ) -> Result<InternalMintEntry> {
        receipt
            .verify_commitment()
            .map_err(|e| EconomyError::Invalid(format!("mint commitment inválido: {e}")))?;

        let nullifier_hex = hex::encode(receipt.nullifier);
        if !self.seen_nullifiers.insert(nullifier_hex.clone()) {
            return Err(EconomyError::Conflict(format!(
                "mint nullifier já contabilizado: {nullifier_hex}"
            )));
        }

        let reference_usdc_micros =
            policy.myc_to_usdc(receipt.amount) / MINT_TO_MICRO_DIVISOR;

        let entry = InternalMintEntry {
            epoch: receipt.epoch,
            beneficiary: receipt.beneficiary.to_string(),
            asset: SyntheticAsset::SyntheticMyc,
            myc_base_units: receipt.amount,
            usdc_per_myc: policy.usdc_per_myc,
            reference_usdc_micros,
            chronicle_hex: hex::encode(receipt.chronicle_hash),
            nullifier_hex,
            external_paid_demand_delta_micros: 0,
        };

        self.total_minted_myc_base = self.total_minted_myc_base.saturating_add(receipt.amount);
        self.total_reference_usdc_micros = self
            .total_reference_usdc_micros
            .saturating_add(reference_usdc_micros);
        self.entries.push(entry.clone());

        Ok(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use mycelium_core::{ContentId, NodeId};
    use mycelium_mint::{MainnetMintEngine, MonetaryPolicy, SporocarpAttestation, WorkClaim, COIN};
    use mycelium_nutrients::TxKind;
    use std::collections::HashMap;

    #[test]
    fn records_internal_mint_without_inflating_external_paid_demand() {
        let val_sk = SigningKey::from_bytes(&[5u8; 32]);
        let val_pk = val_sk.verifying_key().to_bytes();
        let mut sporocarps = HashMap::new();
        sporocarps.insert(NodeId::derive(&val_pk), val_pk);

        let mut policy = MonetaryPolicy::mainnet();
        policy.initial_epoch_budget = 5 * COIN; // 5 MYC = 40 USDC
        policy.max_node_share_bps = 10_000;
        policy.min_hashcash_bits = 4;

        let mut engine =
            MainnetMintEngine::genesis("mycelium-eco-test", b"seed", policy.clone(), sporocarps, 1)
                .unwrap();

        let producer = NodeId::derive(b"eco-producer");
        let client = SigningKey::from_bytes(&[6u8; 32]);
        let claim = WorkClaim::build_signed(
            "mycelium-eco-test",
            0,
            producer,
            &client,
            ContentId::of(b"eco-work-1"),
            TxKind::Seeding,
            20,
            5_000,
            5_000,
            4,
        );
        let root = engine.compute_batch_root(0, &[claim.clone()]);
        let att = SporocarpAttestation::sign("mycelium-eco-test", 0, root, &val_sk);
        let receipts = engine.settle_epoch(&[claim], &[att]).unwrap();

        let mut acc = InternalMintAccounting::new();
        let entry = acc.record_mint_receipt(&receipts[0], &policy).unwrap();

        assert_eq!(entry.asset, SyntheticAsset::SyntheticMyc);
        assert_eq!(entry.usdc_per_myc, 8);
        assert_eq!(entry.myc_base_units, 5 * COIN);
        assert_eq!(entry.reference_usdc_micros, 40_000_000); // 40.000000 USDC
        assert_eq!(entry.external_paid_demand_delta_micros, 0);
        assert_eq!(acc.external_paid_demand_micros, 0);

        // Replay bloqueado pelo nullifier.
        let dup = acc.record_mint_receipt(&receipts[0], &policy);
        assert!(matches!(dup, Err(EconomyError::Conflict(_))));
    }
}
