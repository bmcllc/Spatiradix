use crate::error::MintError;
use mycelium_nutrients::TxKind;
use serde::{Deserialize, Serialize};

/// 1 MYC = 100_000_000 unidades base (8 casas decimais).
pub const COIN: u64 = 100_000_000;

/// Paridade de referência da mainnet: 1 MYC = 8 USDC.
pub const DEFAULT_USDC_PER_MYC: u64 = 8;

/// Razão de lastro de reserva do `mycelium-mint` para a moeda unificada da plataforma (CPX):
/// 1 MYC em reserva lastreia 8 CPX operacionais (paridade 1 CPX = 1 USDC ref).
pub const DEFAULT_CPX_PER_MYC: u64 = DEFAULT_USDC_PER_MYC;

/// Suprimento máximo padrão da mainnet: 21 milhões de MYC.
pub const DEFAULT_MAX_SUPPLY: u64 = 21_000_000 * COIN;

/// Orçamento inicial por época: 50 MYC.
pub const DEFAULT_INITIAL_EPOCH_BUDGET: u64 = 50 * COIN;

/// Intervalo padrão de halving (em épocas).
pub const DEFAULT_HALVING_EPOCHS: u64 = 210_000;

/// Teto padrão de captura por nó em uma única época (500 bps = 5%).
pub const DEFAULT_MAX_NODE_SHARE_BPS: u64 = 500;

/// Dificuldade mínima padrão de hashcash SHA3-256 (em zero bits) para anti-Sybil.
pub const DEFAULT_MIN_HASHCASH_BITS: u8 = 12;

/// Política monetária determinística da mainnet.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonetaryPolicy {
    pub max_supply: u64,
    /// Paridade de referência em USDC por 1 MYC (padrão: 8 USDC).
    pub usdc_per_myc: u64,
    pub initial_epoch_budget: u64,
    pub halving_epochs: u64,
    /// Limite máximo que um único nó pode capturar em uma época, em basis points (10_000 = 100%).
    pub max_node_share_bps: u64,
    /// Dificuldade mínima de `mycelium_zkp::HashcashProof` (0..=24).
    pub min_hashcash_bits: u8,
    /// Peso relativo por unidade de trabalho útil (Seeding).
    pub weight_seeding: u64,
    /// Peso relativo por unidade de trabalho útil (Compute / re-provm).
    pub weight_compute: u64,
    /// Peso relativo por unidade de trabalho útil (Relay).
    pub weight_relay: u64,
}

impl MonetaryPolicy {
    /// Configuração padrão de produção para a mainnet.
    pub fn mainnet() -> Self {
        Self {
            max_supply: DEFAULT_MAX_SUPPLY,
            usdc_per_myc: DEFAULT_USDC_PER_MYC,
            initial_epoch_budget: DEFAULT_INITIAL_EPOCH_BUDGET,
            halving_epochs: DEFAULT_HALVING_EPOCHS,
            max_node_share_bps: DEFAULT_MAX_NODE_SHARE_BPS,
            min_hashcash_bits: DEFAULT_MIN_HASHCASH_BITS,
            weight_seeding: 2,
            weight_compute: 5,
            weight_relay: 1,
        }
    }

    /// Valida invariantes estruturais da política monetária.
    pub fn validate(&self) -> Result<(), MintError> {
        if self.max_supply == 0 {
            return Err(MintError::InvalidPolicy("max_supply deve ser maior que zero"));
        }
        if self.usdc_per_myc == 0 {
            return Err(MintError::InvalidPolicy(
                "usdc_per_myc deve ser maior que zero",
            ));
        }
        if self.initial_epoch_budget == 0 {
            return Err(MintError::InvalidPolicy(
                "initial_epoch_budget deve ser maior que zero",
            ));
        }
        if self.halving_epochs == 0 {
            return Err(MintError::InvalidPolicy(
                "halving_epochs deve ser maior que zero",
            ));
        }
        if self.max_node_share_bps == 0 || self.max_node_share_bps > 10_000 {
            return Err(MintError::InvalidPolicy(
                "max_node_share_bps deve estar entre 1 e 10_000",
            ));
        }
        if self.min_hashcash_bits > 24 {
            return Err(MintError::InvalidPolicy(
                "min_hashcash_bits deve ser <= 24 (limite de hashcash_mint_proof)",
            ));
        }
        Ok(())
    }

    /// Calcula o orçamento máximo cunhável na época `epoch` dado o `current_supply`.
    pub fn epoch_budget(&self, epoch: u64, current_supply: u64) -> u64 {
        let remaining = self.max_supply.saturating_sub(current_supply);
        if remaining == 0 {
            return 0;
        }
        let halvings = epoch / self.halving_epochs;
        if halvings >= 64 {
            return 0;
        }
        let scheduled = self.initial_epoch_budget >> (halvings as u32);
        scheduled.min(remaining)
    }

    /// Limite máximo que um único nó pode receber em uma época (anti-baleia).
    pub fn node_cap(&self, epoch_budget: u64) -> u64 {
        ((epoch_budget as u128 * self.max_node_share_bps as u128) / 10_000) as u64
    }

    /// Peso base por tipo de trabalho útil (`TxKind`).
    pub fn kind_multiplier(&self, kind: TxKind) -> u64 {
        match kind {
            TxKind::Seeding => self.weight_seeding,
            TxKind::Compute => self.weight_compute,
            TxKind::Relay => self.weight_relay,
            TxKind::Consumption | TxKind::Equity | TxKind::Royalty | TxKind::Revenue => 0,
        }
    }

    /// Calcula o peso efetivo combinando tipo de trabalho, unidades entregues e reputação (0.5x..1.5x).
    pub fn effective_weight(&self, kind: TxKind, units: u64, spores: u64, resilience: u64) -> u64 {
        let base = units.saturating_mul(self.kind_multiplier(kind));
        if base == 0 {
            return 0;
        }
        let rep_bonus = spores.saturating_add(resilience).min(10_000);
        let rep_bps = 5_000u128 + rep_bonus as u128;
        ((base as u128 * rep_bps) / 10_000) as u64
    }

    /// Converte unidades base de MYC (8 casas) para equivalente em unidades base de USDC (8 casas).
    pub fn myc_to_usdc(&self, myc_base_units: u64) -> u128 {
        myc_base_units as u128 * self.usdc_per_myc as u128
    }

    /// Converte unidades base de USDC (8 casas) para unidades base de MYC (8 casas).
    pub fn usdc_to_myc(&self, usdc_base_units: u128) -> u64 {
        (usdc_base_units / self.usdc_per_myc as u128) as u64
    }

    /// Capacidade máxima de emissão de CPX (8 casas) lastreada por `myc_base_units` em reserva.
    pub fn myc_reserve_to_cpx(&self, myc_base_units: u64) -> u128 {
        myc_base_units as u128 * self.usdc_per_myc as u128
    }
}
