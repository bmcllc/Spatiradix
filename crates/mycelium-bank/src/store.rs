//! Persistência local do banco (contas + ledger) em `{root}/bank/`.

use crate::accounts::Portfolio;
use crate::error::BankError;
use crate::ledger::SovereignLedger;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct AccountsFile {
    portfolio: Portfolio,
}

#[derive(Clone)]
pub struct BankStore {
    pub root: PathBuf,
    pub portfolio: Portfolio,
    pub ledger: SovereignLedger,
}

impl BankStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, BankError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        let ledger = SovereignLedger::open(&root)?;
        let portfolio = if root.join("accounts.json").exists() {
            let bytes = fs::read(root.join("accounts.json"))?;
            let f: AccountsFile = serde_json::from_slice(&bytes)?;
            f.portfolio
        } else {
            Portfolio::default()
        };
        Ok(Self {
            root,
            portfolio,
            ledger,
        })
    }

    pub fn save_accounts(&self) -> Result<(), BankError> {
        let bytes = serde_json::to_vec_pretty(&AccountsFile {
            portfolio: self.portfolio.clone(),
        })?;
        fs::write(self.root.join("accounts.json"), bytes)?;
        Ok(())
    }

    pub fn account(&self, id: &str) -> Option<&crate::accounts::Account> {
        self.portfolio.get(id)
    }

    pub fn open_account(
        &mut self,
        id: &str,
        owner: &str,
        now: u64,
    ) -> Result<&mut crate::accounts::Account, BankError> {
        let _ = self.portfolio.open_account(id, owner, now)?;
        self.save_accounts()?;
        Ok(self.portfolio.get_mut(id).unwrap())
    }

    /// Crédito com recibo no ledger.
    pub fn credit(
        &mut self,
        account_id: &str,
        asset_symbol: &str,
        micros: i64,
        ref_id: &str,
        now: u64,
    ) -> Result<(), BankError> {
        let asset = crate::assets::Asset::from_symbol(asset_symbol)?;
        {
            let acc = self
                .portfolio
                .get_mut(account_id)
                .ok_or_else(|| BankError::NotFound(account_id.into()))?;
            acc.credit(asset, micros)?;
        }
        self.ledger.append(crate::ledger::Entry::Credit {
            account_id: account_id.into(),
            asset: asset.symbol(),
            micros,
            ref_id: ref_id.into(),
            at: now,
        })?;
        self.save_accounts()?;
        Ok(())
    }
}
