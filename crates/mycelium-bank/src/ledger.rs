use crate::assets::Amount;
use crate::error::BankError;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Entry {
    AccountOpened {
        account_id: String,
        owner: String,
        at: u64,
    },
    Credit {
        account_id: String,
        asset: String,
        micros: i64,
        ref_id: String,
        at: u64,
    },
    Debit {
        account_id: String,
        asset: String,
        micros: i64,
        ref_id: String,
        at: u64,
    },
    Transfer {
        from: String,
        to: String,
        asset: String,
        micros: i64,
        ref_id: String,
        at: u64,
    },
    Trade {
        order_id: String,
        asset_in: String,
        asset_out: String,
        qty_in: i64,
        qty_out: i64,
        at: u64,
    },
    PaymentNfc {
        payment_id: String,
        from: String,
        to: String,
        asset: String,
        micros: i64,
        nfc_proof: String,
        at: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub seq: u64,
    pub prev_hash: String,
    pub record_hash: String,
    pub entry: Entry,
}

impl Record {
    pub fn compute_hash(&self) -> String {
        // Hash over (seq, prev_hash, canonical entry) com record_hash zerado.
        let mut tmp = self.clone();
        tmp.record_hash.clear();
        let bytes = serde_json::to_vec(&tmp).unwrap_or_default();
        blake3::hash(&bytes).to_hex().to_string()
    }
}

#[derive(Clone)]
pub struct SovereignLedger {
    pub root: PathBuf,
    pub path: PathBuf,
}

impl SovereignLedger {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, BankError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        let path = root.join("bank-ledger.jsonl");
        Ok(Self { root, path })
    }

    pub fn ledger_path(&self) -> &Path {
        &self.path
    }

    pub fn append(&self, entry: Entry) -> Result<Record, BankError> {
        let (prev, seq) = self.tail()?;
        let mut rec = Record {
            seq: seq + 1,
            prev_hash: prev,
            record_hash: String::new(),
            entry,
        };
        rec.record_hash = rec.compute_hash();
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(f, "{}", serde_json::to_string(&rec)?)?;
        f.flush()?;
        Ok(rec)
    }

    pub fn tail(&self) -> Result<(String, u64), BankError> {
        if !self.path.exists() {
            return Ok((GENESIS.to_string(), 0));
        }
        let f = File::open(&self.path)?;
        let r = BufReader::new(f);
        let mut last: Option<Record> = None;
        let mut seq = 0u64;
        for line in r.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let rec: Record = serde_json::from_str(&line)?;
            // verify chain
            if rec.seq != seq + 1 {
                return Err(BankError::Conflict("sequência quebrada".into()));
            }
            let expected_prev = last
                .as_ref()
                .map(|r| r.record_hash.clone())
                .unwrap_or_else(|| GENESIS.to_string());
            if rec.prev_hash != expected_prev {
                return Err(BankError::Conflict("prev_hash inválido".into()));
            }
            if rec.record_hash != rec.compute_hash() {
                return Err(BankError::Conflict("record_hash inválido".into()));
            }
            last = Some(rec);
            seq += 1;
        }
        Ok((
            last.map(|r| r.record_hash)
                .unwrap_or_else(|| GENESIS.to_string()),
            seq,
        ))
    }

    pub fn read_all(&self) -> Result<Vec<Record>, BankError> {
        if !self.path.exists() {
            return Ok(vec![]);
        }
        let f = File::open(&self.path)?;
        let r = BufReader::new(f);
        let mut out = vec![];
        for line in r.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            out.push(serde_json::from_str(&line)?);
        }
        Ok(out)
    }

    pub fn audit(&self) -> Result<bool, BankError> {
        let _ = self.tail()?;
        Ok(true)
    }
}

// Amount helper conversion (not used widely)
pub fn amount_asset(a: &Amount) -> String {
    a.asset.symbol()
}
