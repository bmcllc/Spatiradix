//! Local archival store for payment intents.
//!
//! Production path: XChaCha20-Poly1305 authenticated ciphertext inside private
//! SporeBank plots; the lookup index is encrypted too. Nothing is gossiped.
//! Legacy plaintext support is read-only for isolated migration tooling
//! and compatibility tests, NOT accepted by the runtime's financial dispatch.

use crate::core::PaymentIntent;
use crate::error::GatewayError;
use crate::sovereign_cipher::SovereignCipher;
use giggs::{Leaf, Plot};
use mycelium_core::{ContentId, NodeId};
use mycelium_sporebank::SporeBank;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

const INDEX_AAD_DOMAIN: &[u8] = b"mycelium/meta-gateway/index/v1";
const INTENT_AAD_DOMAIN: &[u8] = b"mycelium/meta-gateway/intent/v1";

#[derive(Debug, Default, Serialize, Deserialize)]
struct GatewayIntentIndex {
    by_intent: HashMap<String, ContentId>,
    by_external_ref: HashMap<String, String>,
}

pub struct SporebankIntentStore {
    author: NodeId,
    index_path: PathBuf,
    bank: SporeBank,
    index: GatewayIntentIndex,
    cipher: Option<SovereignCipher>,
}

fn index_aad(author: NodeId) -> Vec<u8> {
    let mut data = Vec::with_capacity(INDEX_AAD_DOMAIN.len() + 32);
    data.extend_from_slice(INDEX_AAD_DOMAIN);
    data.extend_from_slice(&author.0);
    data
}

fn intent_aad(author: NodeId, intent_id: &str, parent: Option<ContentId>) -> Vec<u8> {
    let mut data = Vec::with_capacity(INTENT_AAD_DOMAIN.len() + 32 + 64 + 72);
    data.extend_from_slice(INTENT_AAD_DOMAIN);
    data.extend_from_slice(&author.0);
    data.extend_from_slice(&(intent_id.len() as u64).to_be_bytes());
    data.extend_from_slice(intent_id.as_bytes());
    match parent {
        Some(cid) => {
            data.push(1);
            data.extend_from_slice(cid.to_string().as_bytes());
        }
        None => data.push(0),
    }
    data
}

impl SporebankIntentStore {
    /// Only for reading old local plaintext indexes and existing compatibility tests.
    /// Do not attach a legacy store to a financial dispatching engine.
    pub fn open(home: impl AsRef<Path>, author: NodeId) -> Result<Self, GatewayError> {
        Self::open_inner(home.as_ref(), author, None)
    }

    /// The key MUST originate from an independently protected user secret.
    /// Do not derive it from a public NodeId or the intent's signature.
    pub fn open_encrypted(
        home: impl AsRef<Path>,
        author: NodeId,
        key: [u8; 32],
    ) -> Result<Self, GatewayError> {
        Self::open_inner(home.as_ref(), author, Some(SovereignCipher::new(key)))
    }

    /// Separate derivation domain via the existing Mycelium Keyring (BIP-39).
    pub fn open_with_keyring(
        home: impl AsRef<Path>,
        author: NodeId,
        keys: &mycelium_keyring::Keyring,
    ) -> Result<Self, GatewayError> {
        Self::open_inner(
            home.as_ref(),
            author,
            Some(SovereignCipher::from_keyring(keys)),
        )
    }

    fn open_inner(
        home: &Path,
        author: NodeId,
        cipher: Option<SovereignCipher>,
    ) -> Result<Self, GatewayError> {
        let encrypted = cipher.is_some();
        let index_path = home.join(if encrypted {
            "meta_gateway_index.enc"
        } else {
            "meta_gateway_index.json"
        });
        let incompatible_index = home.join(if encrypted {
            "meta_gateway_index.json"
        } else {
            "meta_gateway_index.enc"
        });
        if incompatible_index.exists() {
            return Err(GatewayError::Crypto(
                "a gateway index of another storage mode exists: explicit migration required"
                    .into(),
            ));
        }
        let index = if index_path.exists() {
            if std::fs::symlink_metadata(&index_path)
                .map_err(|e| GatewayError::Crypto(format!("gateway index metadata: {e}")))?
                .file_type()
                .is_symlink()
            {
                return Err(GatewayError::Crypto(
                    "gateway index symlink forbidden".into(),
                ));
            }
            let bytes = std::fs::read(&index_path)
                .map_err(|e| GatewayError::Crypto(format!("read gateway index: {e}")))?;
            let payload = match &cipher {
                Some(c) => c.open(&bytes, &index_aad(author))?,
                None => bytes,
            };
            serde_json::from_slice(&payload)
                .map_err(|e| GatewayError::Crypto(format!("parse gateway index: {e}")))?
        } else {
            GatewayIntentIndex::default()
        };
        let bank = SporeBank::open(home)
            .map_err(|e| GatewayError::Crypto(format!("sporebank open: {e}")))?;
        Ok(Self {
            author,
            index_path,
            bank,
            index,
            cipher,
        })
    }

    pub fn is_encrypted(&self) -> bool {
        self.cipher.is_some()
    }

    pub fn persist_intent(
        &mut self,
        intent: &PaymentIntent,
        external_ref: Option<&str>,
    ) -> Result<ContentId, GatewayError> {
        // Legacy plaintext mode is READ-ONLY. No new payment data in cleartext.
        if self.cipher.is_none() {
            return Err(GatewayError::AdapterUnavailable("encrypted-intent-store"));
        }
        if let Some(ext) = external_ref {
            if let Some(other) = self.index.by_external_ref.get(ext) {
                if other != &intent.id {
                    return Err(GatewayError::Crypto(
                        "external reference already bound to a different intent".into(),
                    ));
                }
            }
        }
        let parent = self.index.by_intent.get(&intent.id).copied();
        let parents: Vec<ContentId> = parent.into_iter().collect();
        let serialized = serde_json::to_vec(intent)
            .map_err(|e| GatewayError::Crypto(format!("serialize intent: {e}")))?;
        let content = match &self.cipher {
            Some(cipher) => {
                cipher.seal(&serialized, &intent_aad(self.author, &intent.id, parent))?
            }
            None => serialized,
        };
        let plot = Plot {
            author: self.author,
            message: if self.is_encrypted() {
                "[private] meta-gateway:sealed".into()
            } else {
                format!(
                    "[private] meta-gateway:{}:{}",
                    intent.id,
                    intent.state.label()
                )
            },
            parents,
            leaves: vec![Leaf {
                path: if self.is_encrypted() {
                    "sealed-intent.bin".into()
                } else {
                    format!("intent/{}.json", intent.id)
                },
                content,
            }],
        };
        let cid = self
            .bank
            .deposit(plot)
            .map_err(|e| GatewayError::Crypto(format!("sporebank deposit: {e}")))?;
        let prior_cid = self.index.by_intent.insert(intent.id.clone(), cid);
        let prior_external = external_ref.map(|ext| {
            (
                ext.to_string(),
                self.index
                    .by_external_ref
                    .insert(ext.to_string(), intent.id.clone()),
            )
        });
        if let Err(error) = self.save_index() {
            match prior_cid {
                Some(previous) => {
                    self.index.by_intent.insert(intent.id.clone(), previous);
                }
                None => {
                    self.index.by_intent.remove(&intent.id);
                }
            }
            if let Some((reference, previous)) = prior_external {
                match previous {
                    Some(previous) => {
                        self.index.by_external_ref.insert(reference, previous);
                    }
                    None => {
                        self.index.by_external_ref.remove(&reference);
                    }
                }
            }
            return Err(error);
        }
        Ok(cid)
    }

    pub fn load_by_id(&self, intent_id: &str) -> Result<Option<PaymentIntent>, GatewayError> {
        let Some(cid) = self.index.by_intent.get(intent_id) else {
            return Ok(None);
        };
        let plot = self.bank.recall(cid).ok_or_else(|| {
            GatewayError::Crypto("gateway index references a missing SporeBank plot".into())
        })?;
        if plot.author != self.author {
            return Err(GatewayError::Crypto("gateway plot author mismatch".into()));
        }
        let leaf = plot
            .leaves
            .first()
            .ok_or_else(|| GatewayError::Crypto("gateway plot missing payload".into()))?;
        let payload = match &self.cipher {
            Some(cipher) => {
                if plot.message != "[private] meta-gateway:sealed"
                    || plot.leaves.len() != 1
                    || leaf.path != "sealed-intent.bin"
                    || plot.parents.len() > 1
                {
                    return Err(GatewayError::Crypto(
                        "gateway encrypted plot header mismatch".into(),
                    ));
                }
                cipher.open(
                    &leaf.content,
                    &intent_aad(self.author, intent_id, plot.parents.first().copied()),
                )?
            }
            None => leaf.content.clone(),
        };
        let intent: PaymentIntent = serde_json::from_slice(&payload)
            .map_err(|e| GatewayError::Crypto(format!("decode intent from sporebank: {e}")))?;
        if intent.id != intent_id {
            return Err(GatewayError::Crypto("gateway intent ID mismatch".into()));
        }
        Ok(Some(intent))
    }

    pub fn load_by_external_ref(
        &self,
        external_ref: &str,
    ) -> Result<Option<PaymentIntent>, GatewayError> {
        let Some(intent_id) = self.index.by_external_ref.get(external_ref) else {
            return Ok(None);
        };
        self.load_by_id(intent_id)
    }

    pub fn latest_cid(&self, intent_id: &str) -> Option<ContentId> {
        self.index.by_intent.get(intent_id).copied()
    }

    fn save_index(&self) -> Result<(), GatewayError> {
        let serialized = serde_json::to_vec(&self.index)
            .map_err(|e| GatewayError::Crypto(format!("serialize gateway index: {e}")))?;
        let bytes = match &self.cipher {
            Some(cipher) => cipher.seal(&serialized, &index_aad(self.author))?,
            None => serialized,
        };
        let directory = self
            .index_path
            .parent()
            .ok_or_else(|| GatewayError::Crypto("gateway index has no parent directory".into()))?;
        let mut staged = tempfile::NamedTempFile::new_in(directory)
            .map_err(|e| GatewayError::Crypto(format!("create gateway index temp: {e}")))?;
        staged
            .write_all(&bytes)
            .map_err(|e| GatewayError::Crypto(format!("write gateway index temp: {e}")))?;
        staged
            .as_file()
            .sync_all()
            .map_err(|e| GatewayError::Crypto(format!("sync gateway index temp: {e}")))?;
        staged
            .persist(&self.index_path)
            .map_err(|e| GatewayError::Crypto(format!("persist gateway index: {}", e.error)))?;
        #[cfg(unix)]
        std::fs::File::open(directory)
            .and_then(|dir| dir.sync_all())
            .map_err(|e| GatewayError::Crypto(format!("sync gateway directory: {e}")))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{PaymentIntent, MICRO_UNIT};
    use serde_json::json;

    fn sample() -> PaymentIntent {
        PaymentIntent::auto_route(
            5 * MICRO_UNIT,
            "MYC",
            "did:mycelium:secret",
            "myc:private-target",
            json!({"memo":"secret-message"}),
        )
        .unwrap()
    }

    #[test]
    fn ciphertext_and_index_do_not_contain_payment_details_and_recover() {
        let home = tempfile::tempdir().unwrap();
        let owner = NodeId::derive(b"owner");
        let key = [0x7f; 32];
        let intent = sample();
        let id = intent.id.clone();
        let cid;
        {
            let mut vault = SporebankIntentStore::open_encrypted(home.path(), owner, key).unwrap();
            assert!(vault.is_encrypted());
            cid = vault
                .persist_intent(&intent, Some("bank-secret-123"))
                .unwrap();
            assert_eq!(
                vault.load_by_id(&id).unwrap().unwrap().receiver_id,
                "myc:private-target"
            );
            assert_eq!(
                vault
                    .load_by_external_ref("bank-secret-123")
                    .unwrap()
                    .unwrap()
                    .id,
                id
            );
        }
        let raw_index = std::fs::read(home.path().join("meta_gateway_index.enc")).unwrap();
        assert!(raw_index.starts_with(b"MYCGWAE1"));
        for sensitive in ["bank-secret-123", &id, "private-target", "secret-message"] {
            assert!(!String::from_utf8_lossy(&raw_index).contains(sensitive));
        }
        let bank = SporeBank::open(home.path()).unwrap();
        let plot = bank.recall(&cid).unwrap();
        assert_eq!(plot.message, "[private] meta-gateway:sealed");
        assert_eq!(plot.leaves[0].path, "sealed-intent.bin");
        for sensitive in [
            "did:mycelium:secret",
            "private-target",
            "secret-message",
            &id,
        ] {
            assert!(!String::from_utf8_lossy(&plot.leaves[0].content).contains(sensitive));
        }
        let restored = SporebankIntentStore::open_encrypted(home.path(), owner, key).unwrap();
        assert_eq!(restored.load_by_id(&id).unwrap().unwrap().id, id);
        assert!(SporebankIntentStore::open_encrypted(home.path(), owner, [0u8; 32]).is_err());
        assert!(SporebankIntentStore::open(home.path(), owner).is_err());
    }

    #[test]
    fn forbids_silent_downgrade_or_upgrade_of_existing_plaintext() {
        let home = tempfile::tempdir().unwrap();
        let owner = NodeId::derive(b"owner");
        let mut legacy = SporebankIntentStore::open(home.path(), owner).unwrap();
        assert!(legacy.persist_intent(&sample(), None).is_err());
        // Simulate an actual plaintext legacy index that requires an explicit migration.
        std::fs::write(
            home.path().join("meta_gateway_index.json"),
            br#"{"by_intent":{},"by_external_ref":{}}"#,
        )
        .unwrap();
        assert!(SporebankIntentStore::open_encrypted(home.path(), owner, [0x22; 32]).is_err());
        assert!(SporebankIntentStore::open(home.path(), owner).is_ok());
    }

    #[test]
    fn corrupted_encrypted_index_is_rejected_without_resetting_history() {
        let home = tempfile::tempdir().unwrap();
        let owner = NodeId::derive(b"owner");
        let key = [0x19; 32];
        let mut store = SporebankIntentStore::open_encrypted(home.path(), owner, key).unwrap();
        store
            .persist_intent(&sample(), Some("external-001"))
            .unwrap();
        drop(store);
        let index_path = home.path().join("meta_gateway_index.enc");
        let mut original = std::fs::read(&index_path).unwrap();
        *original.last_mut().unwrap() ^= 0x01;
        std::fs::write(&index_path, &original).unwrap();
        assert!(SporebankIntentStore::open_encrypted(home.path(), owner, key).is_err());
        assert_eq!(std::fs::read(index_path).unwrap(), original);
    }

    #[test]
    fn wrong_owner_cannot_load_intent_index() {
        let home = tempfile::tempdir().unwrap();
        let owner = NodeId::derive(b"owner");
        let mut vault = SporebankIntentStore::open_encrypted(home.path(), owner, [5; 32]).unwrap();
        vault.persist_intent(&sample(), None).unwrap();
        let stranger = NodeId::derive(b"stranger");
        assert!(SporebankIntentStore::open_encrypted(home.path(), stranger, [5; 32]).is_err());
    }
}
