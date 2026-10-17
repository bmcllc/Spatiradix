use crate::assets::Asset;
use crate::error::BankError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub id: String,
    /// Dono (account_id da carteira).
    pub owner: String,
    pub balances: BTreeMap<Asset, i64>,
    pub created_at_unix: u64,
}

impl Account {
    pub fn new(id: impl Into<String>, owner: impl Into<String>, now: u64) -> Self {
        Self {
            id: id.into(),
            owner: owner.into(),
            balances: BTreeMap::new(),
            created_at_unix: now,
        }
    }

    pub fn balance(&self, asset: Asset) -> i64 {
        self.balances.get(&asset).copied().unwrap_or(0)
    }

    pub fn credit(&mut self, asset: Asset, micros: i64) -> Result<(), BankError> {
        if micros < 0 {
            return Err(BankError::Invalid("crédito negativo".into()));
        }
        *self.balances.entry(asset).or_insert(0) += micros;
        Ok(())
    }

    pub fn debit(&mut self, asset: Asset, micros: i64) -> Result<(), BankError> {
        if micros < 0 {
            return Err(BankError::Invalid("débito negativo".into()));
        }
        let cur = self.balance(asset);
        if cur < micros {
            return Err(BankError::InsufficientFunds);
        }
        *self.balances.entry(asset).or_insert(0) -= micros;
        Ok(())
    }

    pub fn transfer_to(
        &mut self,
        other: &mut Account,
        asset: Asset,
        micros: i64,
    ) -> Result<(), BankError> {
        self.debit(asset, micros)?;
        other.credit(asset, micros)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Portfolio {
    pub accounts: BTreeMap<String, Account>,
}

impl Portfolio {
    pub fn open_account(
        &mut self,
        id: &str,
        owner: &str,
        now: u64,
    ) -> Result<&mut Account, BankError> {
        if self.accounts.contains_key(id) {
            return Err(BankError::Conflict("conta já existe".into()));
        }
        self.accounts
            .insert(id.to_string(), Account::new(id, owner, now));
        Ok(self.accounts.get_mut(id).unwrap())
    }

    pub fn get(&self, id: &str) -> Option<&Account> {
        self.accounts.get(id)
    }
    pub fn get_mut(&mut self, id: &str) -> Option<&mut Account> {
        self.accounts.get_mut(id)
    }
}
