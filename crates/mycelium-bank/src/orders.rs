use crate::assets::Asset;
use crate::error::BankError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Side {
    Buy,
    Sell,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Order {
    pub id: String,
    pub account_id: String,
    pub base: Asset,
    pub quote: Asset,
    pub side: Side,
    pub price_micros: i64, // price in quote micros per 1 base unit? simplified: quote micros per base micro
    pub qty_micros: i64,
    pub remaining_micros: i64,
    pub created_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trade {
    pub id: String,
    pub buy_order: String,
    pub sell_order: String,
    pub price_micros: i64,
    pub qty_micros: i64,
    pub at: u64,
}

/// Livro de ordens soberano (in-memory). Persistência via ledger externamente.
#[derive(Default)]
pub struct OrderBook {
    pub orders: BTreeMap<String, Order>,
}

impl OrderBook {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn place(&mut self, order: Order) -> Result<String, BankError> {
        if order.remaining_micros <= 0 {
            return Err(BankError::Invalid("qty <= 0".into()));
        }
        if self.orders.contains_key(&order.id) {
            return Err(BankError::Conflict("order exists".into()));
        }
        let id = order.id.clone();
        self.orders.insert(id.clone(), order);
        Ok(id)
    }

    /// Matching price-time priority simplificado: compra executa contra venda com price <= buy price.
    pub fn match_orders(&mut self, now: u64) -> Vec<Trade> {
        let mut trades = vec![];
        // Collect candidate pairs
        let ids: Vec<String> = self.orders.keys().cloned().collect();
        // Simple O(n^2) matching for MVP.
        for i in 0..ids.len() {
            for j in (i + 1)..ids.len() {
                let a = self.orders.get(&ids[i]).cloned();
                let b = self.orders.get(&ids[j]).cloned();
                if a.is_none() || b.is_none() {
                    continue;
                }
                let a = a.unwrap();
                let b = b.unwrap();
                if a.base != b.base || a.quote != b.quote {
                    continue;
                }
                if a.side == b.side {
                    continue;
                }
                // identify buy/sell
                let (buy, sell) = if a.side == Side::Buy {
                    (a.clone(), b.clone())
                } else {
                    (b.clone(), a.clone())
                };
                if buy.remaining_micros <= 0 || sell.remaining_micros <= 0 {
                    continue;
                }
                if sell.price_micros > buy.price_micros {
                    continue;
                }
                let price = sell.price_micros;
                let qty = buy.remaining_micros.min(sell.remaining_micros);
                if qty <= 0 {
                    continue;
                }
                trades.push(Trade {
                    id: format!("trade-{}-{}", buy.id, sell.id),
                    buy_order: buy.id.clone(),
                    sell_order: sell.id.clone(),
                    price_micros: price,
                    qty_micros: qty,
                    at: now,
                });
                // update remaining
                if let Some(o) = self.orders.get_mut(&buy.id) {
                    o.remaining_micros -= qty;
                }
                if let Some(o) = self.orders.get_mut(&sell.id) {
                    o.remaining_micros -= qty;
                }
            }
        }
        trades
    }

    pub fn cancel(&mut self, id: &str) -> Result<(), BankError> {
        if self.orders.remove(id).is_none() {
            return Err(BankError::NotFound(id.into()));
        }
        Ok(())
    }
}
