use serde::{Deserialize, Serialize};

/// Ativos suportados pelo banco/corretora. A unidade mínima ("micros") é
/// 1e-6 para todos, preservando comparabilidade entre fiat e cripto.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Asset {
    /// Real brasileiro (off-chain, representado por stable/private claim).
    Brl,
    /// Dólar (off-chain USD).
    Usd,
    /// Stablecoin USDC (on-chain Base).
    Usdc,
    /// BTC.
    Btc,
    /// ETH.
    Eth,
    /// Token nativo de reserva Mycelium (MYC — emitido via `mycelium-mint`).
    Myc,
    /// Moeda unificada da plataforma Mycelium / Cameon PX (CPX — lastreada pela reserva `mycelium-mint`).
    Cpx,
    /// Token genérico emitido por terceiros.
    Token(u32),
}

impl Asset {
    pub fn from_symbol(s: &str) -> Result<Self, crate::error::BankError> {
        match s.to_uppercase().as_str() {
            "BRL" => Ok(Asset::Brl),
            "USD" => Ok(Asset::Usd),
            "USDC" => Ok(Asset::Usdc),
            "BTC" => Ok(Asset::Btc),
            "ETH" => Ok(Asset::Eth),
            "MYC" => Ok(Asset::Myc),
            "CPX" => Ok(Asset::Cpx),
            _ => Err(crate::error::BankError::Invalid(format!("ativo desconhecido: {s}"))),
        }
    }

    pub fn symbol(&self) -> String {
        match self {
            Asset::Brl => "BRL".into(),
            Asset::Usd => "USD".into(),
            Asset::Usdc => "USDC".into(),
            Asset::Btc => "BTC".into(),
            Asset::Eth => "ETH".into(),
            Asset::Myc => "MYC".into(),
            Asset::Cpx => "CPX".into(),
            Asset::Token(i) => format!("TKN{i}"),
        }
    }

    pub fn decimals(&self) -> u8 {
        match self {
            Asset::Btc => 8,
            Asset::Eth => 18,
            _ => 6,
        }
    }
}

/// Quantidade em micro-unidades (1e-6 do ativo, com BTC/Eth convertidos).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Amount {
    pub asset: Asset,
    pub micros: i64,
}

impl Amount {
    pub fn new(asset: Asset, micros: i64) -> Self {
        Self { asset, micros }
    }
    pub fn zero(asset: Asset) -> Self {
        Self { asset, micros: 0 }
    }
    pub fn is_negative(&self) -> bool {
        self.micros < 0
    }
}
