//! `SignedPacket` no formato do Pkarr (BEP44 *mutable item*):
//! chave(32) · assinatura(64) · timestamp µs (8, big-endian) · DNS (≤ 1000 B).
//!
//! A assinatura cobre o bencode `3:seqi<ts>e1:v<len>:<dns>`, exatamente o que
//! os nós da Mainline DHT e os relays Pkarr verificam.

use crate::PkarrError;
use ed25519_dalek::hazmat::{raw_sign, ExpandedSecretKey};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::Sha512;

pub const MAX_DNS_BYTES: usize = 1000;
/// Tamanho máximo do corpo do relay: assinatura + timestamp + DNS.
pub const MAX_RELAY_PAYLOAD: usize = 64 + 8 + MAX_DNS_BYTES;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedPacket {
    public_key: [u8; 32],
    signature: [u8; 64],
    timestamp_us: u64,
    dns: Vec<u8>,
}

pub fn signable(timestamp_us: u64, dns: &[u8]) -> Vec<u8> {
    let mut out = format!("3:seqi{timestamp_us}e1:v{}:", dns.len()).into_bytes();
    out.extend_from_slice(dns);
    out
}

impl SignedPacket {
    /// Assina com uma chave ed25519 comum (modo público, não anônimo).
    pub fn sign(key: &SigningKey, timestamp_us: u64, dns: Vec<u8>) -> Result<Self, PkarrError> {
        check_dns_len(&dns)?;
        let sig = key.sign(&signable(timestamp_us, &dns));
        Ok(Self {
            public_key: key.verifying_key().to_bytes(),
            signature: sig.to_bytes(),
            timestamp_us,
            dns,
        })
    }

    /// Assina com um escalar expandido (chave cegada — ver `blind`).
    pub(crate) fn sign_expanded(
        esk: &ExpandedSecretKey,
        vk: &VerifyingKey,
        timestamp_us: u64,
        dns: Vec<u8>,
    ) -> Result<Self, PkarrError> {
        check_dns_len(&dns)?;
        let sig = raw_sign::<Sha512>(esk, &signable(timestamp_us, &dns), vk);
        let packet = Self {
            public_key: vk.to_bytes(),
            signature: sig.to_bytes(),
            timestamp_us,
            dns,
        };
        // Nunca publicar algo que nós mesmos não conseguimos verificar.
        packet.verify()?;
        Ok(packet)
    }

    /// Verificação estrita (rejeita chaves de ordem pequena e assinaturas
    /// maleáveis).
    pub fn verify(&self) -> Result<(), PkarrError> {
        check_dns_len(&self.dns)?;
        let vk = VerifyingKey::from_bytes(&self.public_key).map_err(|_| PkarrError::BadKey)?;
        let sig = Signature::from_bytes(&self.signature);
        vk.verify_strict(&signable(self.timestamp_us, &self.dns), &sig)
            .map_err(|_| PkarrError::BadSignature)
    }

    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }
    pub fn timestamp_us(&self) -> u64 {
        self.timestamp_us
    }
    pub fn dns(&self) -> &[u8] {
        &self.dns
    }

    /// Corpo do `PUT /<z32>` de um relay Pkarr.
    pub fn to_relay_payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(72 + self.dns.len());
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&self.timestamp_us.to_be_bytes());
        out.extend_from_slice(&self.dns);
        out
    }

    /// Interpreta e **verifica** o corpo devolvido por um relay para a chave
    /// esperada. Nada que falhe a assinatura sai daqui.
    pub fn from_relay_payload(public_key: &[u8; 32], payload: &[u8]) -> Result<Self, PkarrError> {
        if payload.len() < 72 || payload.len() > MAX_RELAY_PAYLOAD {
            return Err(PkarrError::Malformed("tamanho do payload do relay"));
        }
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&payload[..64]);
        let mut ts = [0u8; 8];
        ts.copy_from_slice(&payload[64..72]);
        let packet = Self {
            public_key: *public_key,
            signature,
            timestamp_us: u64::from_be_bytes(ts),
            dns: payload[72..].to_vec(),
        };
        packet.verify()?;
        Ok(packet)
    }
}

fn check_dns_len(dns: &[u8]) -> Result<(), PkarrError> {
    if dns.len() > MAX_DNS_BYTES {
        return Err(PkarrError::Malformed("pacote DNS > 1000 bytes"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_payload_roundtrip_and_tamper() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let p =
            SignedPacket::sign(&key, 1_700_000_000_000_000, b"\x00\x00\x84\x00".to_vec()).unwrap();
        let body = p.to_relay_payload();
        assert_eq!(
            SignedPacket::from_relay_payload(p.public_key(), &body).unwrap(),
            p
        );

        for i in [0usize, 63, 64, 71, body.len() - 1] {
            let mut bad = body.clone();
            bad[i] ^= 1;
            assert!(
                SignedPacket::from_relay_payload(p.public_key(), &bad).is_err(),
                "byte {i}"
            );
        }
        let other = SigningKey::from_bytes(&[8u8; 32])
            .verifying_key()
            .to_bytes();
        assert!(SignedPacket::from_relay_payload(&other, &body).is_err());
    }

    #[test]
    fn oversized_dns_rejected() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        assert!(SignedPacket::sign(&key, 1, vec![0u8; 1001]).is_err());
    }
}
