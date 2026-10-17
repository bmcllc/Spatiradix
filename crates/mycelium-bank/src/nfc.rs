use crate::error::BankError;
use crate::payments::{NfcProof, PaymentIntent};

/// Transporte NFC físico. Implementações concretas vivem em plataformas
/// (Android HCE, iOS CoreNFC, Linux pcsc). O core depende só deste trait.
pub trait NfcTap {
    /// Envia bytes ao peer (out-of-band, tap único).
    fn send(&mut self, payload: &[u8]) -> Result<(), BankError>;
    /// Recebe bytes do peer.
    fn receive(&mut self) -> Result<Vec<u8>, BankError>;
}

/// Formato binário de um tap: intent JSON + proof JSON.
#[derive(Debug, Clone)]
pub struct TapFrame {
    pub intent_bytes: Vec<u8>,
    pub proof_bytes: Vec<u8>,
}

impl TapFrame {
    pub fn encode(intent: &PaymentIntent, proof: &NfcProof) -> Result<Vec<u8>, BankError> {
        let i = serde_json::to_vec(intent)?;
        let p = serde_json::to_vec(proof)?;
        let mut out = Vec::with_capacity(8 + i.len() + p.len());
        out.extend_from_slice(&(i.len() as u32).to_le_bytes());
        out.extend_from_slice(&i);
        out.extend_from_slice(&(p.len() as u32).to_le_bytes());
        out.extend_from_slice(&p);
        Ok(out)
    }

    pub fn decode(buf: &[u8]) -> Result<(PaymentIntent, NfcProof), BankError> {
        if buf.len() < 8 {
            return Err(BankError::Invalid("frame curto".into()));
        }
        let ilen = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
        let mut off = 4;
        if off + ilen + 4 > buf.len() {
            return Err(BankError::Invalid("frame truncado".into()));
        }
        let intent: PaymentIntent = serde_json::from_slice(&buf[off..off + ilen])?;
        off += ilen;
        let plen = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
        off += 4;
        if off + plen > buf.len() {
            return Err(BankError::Invalid("frame truncado".into()));
        }
        let proof: NfcProof = serde_json::from_slice(&buf[off..off + plen])?;
        Ok((intent, proof))
    }
}

/// Helper de tap completo: pagador envia, recebedor valida e responde ack.
pub fn perform_tap<T: NfcTap>(
    transport: &mut T,
    intent: &PaymentIntent,
    proof: &NfcProof,
) -> Result<(), BankError> {
    let frame = TapFrame::encode(intent, proof)?;
    transport.send(&frame)
}
