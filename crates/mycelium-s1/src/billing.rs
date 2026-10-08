//! Administrative credit provisioning. Payment providers must credit only verified settlements.
use crate::{Allowance, Ticket};
use ed25519_dalek::SigningKey;
use fs2::FileExt;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
};

#[derive(Default, Serialize, Deserialize)]
pub struct Ledger {
    pub balances: BTreeMap<String, u64>,
    receipts: BTreeMap<String, (String, u64)>,
    reservations: BTreeMap<String, Ticket>,
}
impl Ledger {
    pub fn credit(&mut self, receipt: &str, studio: &str, amount: u64) -> Result<(), String> {
        if receipt.is_empty() || studio.is_empty() || amount == 0 {
            return Err("invalid credit".into());
        }
        if let Some(prior) = self.receipts.get(receipt) {
            return if prior == &(studio.to_string(), amount) {
                Ok(())
            } else {
                Err("receipt already used with different values".into())
            };
        }
        let balance = self
            .balances
            .get(studio)
            .copied()
            .unwrap_or(0)
            .checked_add(amount)
            .ok_or("balance overflow")?;
        self.balances.insert(studio.into(), balance);
        self.receipts
            .insert(receipt.into(), (studio.into(), amount));
        Ok(())
    }
    pub fn reserve(
        &mut self,
        allowance: Allowance,
        key: &SigningKey,
        now: u64,
    ) -> Result<Ticket, String> {
        if allowance.id.is_empty()
            || allowance.studio.is_empty()
            || allowance.model.is_empty()
            || allowance.device.is_empty()
            || allowance.evaluations == 0
            || allowance.expires_at <= now
        {
            return Err("invalid allowance".into());
        }
        if let Some(prior) = self.reservations.get(&allowance.id) {
            return if serde_json::to_vec(&prior.allowance).unwrap()
                == serde_json::to_vec(&allowance).unwrap()
            {
                Ok(prior.clone())
            } else {
                Err("reservation id conflict".into())
            };
        }
        let balance = self.balances.get(&allowance.studio).copied().unwrap_or(0);
        let remainder = balance
            .checked_sub(allowance.evaluations)
            .ok_or("insufficient credits")?;
        let ticket = Ticket::issue(allowance, key)?;
        self.balances
            .insert(ticket.allowance.studio.clone(), remainder);
        self.reservations
            .insert(ticket.allowance.id.clone(), ticket.clone());
        Ok(ticket)
    }
}
/// A server-owned directory. OS locking serializes processes; atomic rename commits updates.
pub struct Store {
    directory: PathBuf,
    _lock: File,
    pub ledger: Ledger,
    pub issuer: SigningKey,
}
impl Store {
    pub fn open(directory: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        fs::create_dir_all(directory)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(directory.join("ledger.lock"))?;
        lock.try_lock_exclusive()?;
        let key_path = directory.join("issuer.key");
        let issuer = if key_path.exists() {
            let seed: [u8; 32] = fs::read(&key_path)?
                .try_into()
                .map_err(|_| "invalid issuer seed")?;
            SigningKey::from_bytes(&seed)
        } else {
            let mut seed = [0; 32];
            rand::rngs::OsRng.fill_bytes(&mut seed);
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(key_path)?;
            use std::io::Write;
            file.write_all(&seed)?;
            file.sync_all()?;
            SigningKey::from_bytes(&seed)
        };
        let ledger_path = directory.join("ledger.json");
        let ledger = if ledger_path.exists() {
            serde_json::from_slice(&fs::read(ledger_path)?)?
        } else {
            Ledger::default()
        };
        Ok(Self {
            directory: directory.into(),
            _lock: lock,
            ledger,
            issuer,
        })
    }
    pub fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        use std::io::Write;
        let temp = self.directory.join("ledger.pending");
        let mut file = File::create(&temp)?;
        file.write_all(&serde_json::to_vec(&self.ledger)?)?;
        file.sync_all()?;
        fs::rename(temp, self.directory.join("ledger.json"))?;
        #[cfg(unix)]
        File::open(&self.directory)?.sync_all()?;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reservations_debit_once_and_reject_overspend() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let mut ledger = Ledger::default();
        ledger.credit("receipt", "studio", 10).unwrap();
        ledger.credit("receipt", "studio", 10).unwrap();
        assert!(ledger.credit("receipt", "studio", 11).is_err());
        let allowance = Allowance {
            id: "r1".into(),
            studio: "studio".into(),
            model: "npc".into(),
            device: "pc".into(),
            evaluations: 7,
            expires_at: 100,
        };
        let ticket = ledger.reserve(allowance.clone(), &key, 1).unwrap();
        assert_eq!(
            ledger
                .reserve(allowance.clone(), &key, 1)
                .unwrap()
                .signature,
            ticket.signature
        );
        assert_eq!(ledger.balances["studio"], 3);
        let mut conflict = allowance.clone();
        conflict.evaluations = 1;
        assert!(ledger.reserve(conflict, &key, 1).is_err());
        let mut other = allowance;
        other.id = "r2".into();
        assert!(ledger.reserve(other, &key, 1).is_err());
        assert_eq!(ledger.balances["studio"], 3);
    }
}
