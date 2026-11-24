use crate::error::BankError;
use crate::payments::{NfcProof, PaymentIntent};
use base64::Engine as _;
use serde::{Deserialize, Serialize};

/// Tipo externo NFC Forum NDEF para pagamentos GhostID × CPX × Mycelium Pay.
pub const NDEF_EXTERNAL_TYPE: &str = "mycelium.network:ghostpay";
/// Prefixo URI canônico para troca via NFC NDEF / QR Code / Web NFC (`NDEFReader`).
pub const NFC_CPX_URI_PREFIX: &str = "urn:mycelium:nfc:cpx:v1:";

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

/// Envelope interoperável NFC Forum NDEF (TNF=4 External Record) ligando
/// `mycelium-bank` (`PaymentIntent` + `NfcProof` com GhostID), `mycelium-pay`
/// (bytes CBOR opcionais de `PayRequest`/`Envelope`) e a carteira CPX/Rhizome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NfcNdefFrame {
    pub version: u8,
    pub ghost_pubkey_hex: String,
    pub intent: PaymentIntent,
    pub proof: NfcProof,
    #[serde(default)]
    pub pay_envelope_cbor_b64: Option<String>,
}

impl NfcNdefFrame {
    pub fn new(
        ghost_pubkey_xonly: &[u8; 32],
        intent: PaymentIntent,
        proof: NfcProof,
        pay_envelope_cbor: Option<&[u8]>,
    ) -> Self {
        Self {
            version: 1,
            ghost_pubkey_hex: hex::encode(ghost_pubkey_xonly),
            intent,
            proof,
            pay_envelope_cbor_b64: pay_envelope_cbor
                .map(|b| base64::engine::general_purpose::STANDARD.encode(b)),
        }
    }

    /// Serializa como registro binário NDEF padrão NFC Forum (MB=1, ME=1, TNF=0x04 External).
    pub fn encode_ndef_record(&self) -> Result<Vec<u8>, BankError> {
        let payload = serde_json::to_vec(self)?;
        let ty = NDEF_EXTERNAL_TYPE.as_bytes();
        if ty.len() > 255 {
            return Err(BankError::Invalid("tipo NDEF excede 255 bytes".into()));
        }
        let short = payload.len() <= 255;
        let header: u8 = if short { 0xD4 } else { 0xC4 }; // MB|ME|(SR)|TNF=4
        let mut out = Vec::with_capacity(6 + ty.len() + payload.len());
        out.push(header);
        out.push(ty.len() as u8);
        if short {
            out.push(payload.len() as u8);
        } else {
            out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        }
        out.extend_from_slice(ty);
        out.extend_from_slice(&payload);
        Ok(out)
    }

    /// Decodifica e verifica a estrutura de um registro binário NDEF External (`mycelium.network:ghostpay`).
    pub fn decode_ndef_record(buf: &[u8]) -> Result<Self, BankError> {
        if buf.len() < 4 {
            return Err(BankError::Invalid("registro NDEF curto".into()));
        }
        let header = buf[0];
        let tnf = header & 0x07;
        if tnf != 0x04 {
            return Err(BankError::Invalid(format!("TNF NDEF inesperado: {tnf}")));
        }
        let short = (header & 0x10) != 0;
        let type_len = buf[1] as usize;
        let (payload_len, mut off) = if short {
            (buf[2] as usize, 3usize)
        } else {
            if buf.len() < 6 {
                return Err(BankError::Invalid("registro NDEF longo truncado".into()));
            }
            let len = u32::from_be_bytes(buf[2..6].try_into().unwrap()) as usize;
            (len, 6usize)
        };
        if off + type_len + payload_len > buf.len() {
            return Err(BankError::Invalid("payload NDEF truncado".into()));
        }
        let ty = std::str::from_utf8(&buf[off..off + type_len])
            .map_err(|_| BankError::Invalid("tipo NDEF não-UTF8".into()))?;
        if ty != NDEF_EXTERNAL_TYPE {
            return Err(BankError::Invalid(format!("tipo NDEF desconhecido: {ty}")));
        }
        off += type_len;
        let frame: Self = serde_json::from_slice(&buf[off..off + payload_len])?;
        Ok(frame)
    }

    /// Codifica o registro NDEF em URI textual compatível com Web NFC / QR Code / Clipboard.
    pub fn to_uri(&self) -> Result<String, BankError> {
        let ndef = self.encode_ndef_record()?;
        Ok(format!(
            "{NFC_CPX_URI_PREFIX}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(ndef)
        ))
    }

    pub fn from_uri(uri: &str) -> Result<Self, BankError> {
        let b64 = uri
            .trim()
            .strip_prefix(NFC_CPX_URI_PREFIX)
            .ok_or_else(|| BankError::Invalid("prefixo URI NFC CPX inválido".into()))?;
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|e| BankError::Invalid(format!("base64url NFC inválido: {e}")))?;
        Self::decode_ndef_record(&raw)
    }
}
