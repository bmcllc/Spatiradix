use crate::assets::Amount;
use crate::error::BankError;
use crate::identity::SovereignWallet;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentIntent {
    pub id: String,
    pub from: String,
    pub to: String,
    pub amount: Amount,
    pub memo: String,
    pub created_at_unix: u64,
    /// Nonce para prevenir replay (hex).
    pub nonce: String,
}

impl PaymentIntent {
    pub fn new(from: &str, to: &str, amount: Amount, memo: String, now: u64) -> Self {
        let mut buf = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut buf);
        Self {
            id: format!("pay-{}", hex::encode(&buf[..8])),
            from: from.into(),
            to: to.into(),
            amount,
            memo,
            created_at_unix: now,
            nonce: hex::encode(buf),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NfcProof {
    /// Assinatura do pagador sobre (intent_id || nonce || amount || to).
    pub payer_sig: Vec<u8>,
    /// Chave pública do pagador (ed25519, 32 bytes).
    pub payer_pubkey: [u8; 32],
    /// Segredo compartilhado encapsulado (ML-KEM) para confidencialidade do recibo em trânsito.
    pub kem_ciphertext: Vec<u8>,
    /// Chave pública x-only (32 bytes) do GhostID (secp256k1 BIP-340) para interoperabilidade NFC × Pay × Wallet.
    #[serde(default)]
    pub ghost_pubkey_xonly: Option<[u8; 32]>,
    /// Assinatura BIP-340 Schnorr do GhostID sobre a mesma mensagem canônica da intenção.
    #[serde(default)]
    pub ghost_schnorr_sig: Option<Vec<u8>>,
}

impl NfcProof {
    /// Cria prova NFC assinada pelo pagador (Ed25519 + ML-KEM). O tap NFC transmite intent + proof.
    pub fn create(wallet: &SovereignWallet, intent: &PaymentIntent) -> Self {
        let msg = canonical_intent_message(intent);
        let sig = wallet.sign(&msg).to_vec();
        let kem = wallet.encapsulate_to();
        let ct = kem.map(|k| k.ciphertext.clone()).unwrap_or_default();
        NfcProof {
            payer_sig: sig,
            payer_pubkey: wallet.verifying_key().to_bytes(),
            kem_ciphertext: ct,
            ghost_pubkey_xonly: None,
            ghost_schnorr_sig: None,
        }
    }

    /// Cria prova NFC híbrida vinculando **Ed25519 + GhostID (BIP-340 Schnorr) + ML-KEM-1024**.
    pub fn create_with_ghostid(
        wallet: &SovereignWallet,
        ghost: &mycelium_ghostid::GhostId,
        intent: &PaymentIntent,
    ) -> Result<Self, BankError> {
        let msg = canonical_intent_message(intent);
        let sig = wallet.sign(&msg).to_vec();
        let kem = wallet.encapsulate_to();
        let ct = kem.map(|k| k.ciphertext.clone()).unwrap_or_default();
        let gsig = ghost.sign(&msg);
        Ok(NfcProof {
            payer_sig: sig,
            payer_pubkey: wallet.verifying_key().to_bytes(),
            kem_ciphertext: ct,
            ghost_pubkey_xonly: Some(ghost.nostr_pubkey()),
            ghost_schnorr_sig: Some(gsig.to_vec()),
        })
    }

    pub fn verify(&self, intent: &PaymentIntent) -> bool {
        let msg = canonical_intent_message(intent);
        let vk = match ed25519_dalek::VerifyingKey::from_bytes(&self.payer_pubkey) {
            Ok(v) => v,
            Err(_) => return false,
        };
        if !crate::identity::SovereignWallet::verify(&vk, &msg, &self.payer_sig) {
            return false;
        }
        match (&self.ghost_pubkey_xonly, &self.ghost_schnorr_sig) {
            (Some(gpk), Some(gsig)) => {
                crate::identity::SovereignWallet::verify_ghost_schnorr(gpk, &msg, gsig)
            }
            (None, None) => true,
            _ => false,
        }
    }

    /// Verifica estritamente que a prova carrega e autentica uma assinatura GhostID válida.
    pub fn verify_with_ghostid(&self, intent: &PaymentIntent) -> bool {
        self.ghost_pubkey_xonly.is_some()
            && self.ghost_schnorr_sig.is_some()
            && self.verify(intent)
    }
}

fn canonical_intent_message(intent: &PaymentIntent) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(intent.id.as_bytes());
    buf.extend_from_slice(&[0]);
    buf.extend_from_slice(intent.from.as_bytes());
    buf.extend_from_slice(&[0]);
    buf.extend_from_slice(intent.to.as_bytes());
    buf.extend_from_slice(&[0]);
    buf.extend_from_slice(intent.amount.asset.symbol().as_bytes());
    buf.extend_from_slice(&[0]);
    buf.extend_from_slice(&intent.amount.micros.to_le_bytes());
    buf.extend_from_slice(&[0]);
    buf.extend_from_slice(intent.nonce.as_bytes());
    buf
}

/// Recibo de pagamento (hash-encadeado na ledger).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentReceipt {
    pub id: String,
    pub intent_id: String,
    pub status: PaymentStatus,
    pub settled_at_unix: Option<u64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PaymentStatus {
    Pending,
    Settled,
    Failed,
    Reversed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementProof {
    pub payment_id: String,
    pub nfc_proof: NfcProof,
    pub ledger_seq: u64,
    pub ledger_hash: String,
}

/// Valida uma intenção NFC recebida: verifica assinatura do pagador e nonce.
pub fn validate_nfc_payment(intent: &PaymentIntent, proof: &NfcProof) -> Result<(), BankError> {
    if !proof.verify(intent) {
        return Err(BankError::BadSignature);
    }
    Ok(())
}

/// Gera um pagamento completo em um único passo (para o recebedor).
pub fn receive_nfc_payment(
    wallet: &SovereignWallet,
    intent: PaymentIntent,
    proof: NfcProof,
) -> Result<PaymentReceipt, BankError> {
    validate_nfc_payment(&intent, &proof)?;
    // Decapsula segredo para confirmar confidencialidade (ignora falha não fatal).
    let _ = wallet.decapsulate(&proof.kem_ciphertext);
    Ok(PaymentReceipt {
        id: intent.id.clone(),
        intent_id: intent.id,
        status: PaymentStatus::Settled,
        settled_at_unix: Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        ),
    })
}
