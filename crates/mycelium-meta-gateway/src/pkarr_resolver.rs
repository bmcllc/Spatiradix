//! Resolução descentralizada de identidades financeiras via PKARR
//! (`mycelium-pkarr`: pacotes DNS TXT RFC 1035 assinados com Ed25519 e
//! endereçados por chave pública em z-base-32, sem DNS tradicional).

use crate::error::GatewayError;
use ed25519_dalek::SigningKey;
use mycelium_pkarr::dns::{self, TxtRecord};
use mycelium_pkarr::{zbase32, SignedPacket};
use std::collections::HashMap;

/// Subdomínio TXT canônico para descoberta de rotas de pagamento no PKARR.
pub const PKARR_PAY_LABEL: &str = "_mycelium-pay";

/// Cache/resolvedor local de pacotes PKARR verificados criptograficamente.
#[derive(Default, Debug, Clone)]
pub struct PkarrIdentityResolver {
    /// Mapa `zbase32(pubkey) -> SignedPacket` verificado.
    packets: HashMap<String, SignedPacket>,
}

impl PkarrIdentityResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Cria e assina um `SignedPacket` PKARR anunciando uma rota de pagamento
    /// (ex.: `pix:alice@mycelium.net`, `swift:CHASUS33XXX`, `brics:node-09`, `myc:<id>`).
    /// Retorna `(uri_pkarr, packet)` onde `uri_pkarr = "pkarr:<zbase32>"`.
    pub fn sign_payment_record(
        signing_key: &SigningKey,
        timestamp_us: u64,
        target_route: &str,
    ) -> Result<(String, SignedPacket), GatewayError> {
        let z32 = zbase32::encode(signing_key.verifying_key().as_bytes());
        let record = TxtRecord {
            name: format!("{PKARR_PAY_LABEL}.{z32}"),
            ttl: 300,
            strings: dns::split_txt(format!("route={target_route}").as_bytes()),
        };
        let dns_bytes = dns::encode(&[record])
            .map_err(|e| GatewayError::Crypto(format!("pkarr dns encode: {e}")))?;
        let packet = SignedPacket::sign(signing_key, timestamp_us, dns_bytes)
            .map_err(|e| GatewayError::Crypto(format!("pkarr sign: {e}")))?;
        Ok((format!("pkarr:{z32}"), packet))
    }

    /// Registra um `SignedPacket` após verificação estrita da assinatura Ed25519 (BEP44).
    pub fn register_verified_packet(
        &mut self,
        packet: SignedPacket,
    ) -> Result<String, GatewayError> {
        packet
            .verify()
            .map_err(|e| GatewayError::Crypto(format!("pkarr verify falhou: {e}")))?;
        let z32 = zbase32::encode(packet.public_key());
        self.packets.insert(z32.clone(), packet);
        Ok(format!("pkarr:{z32}"))
    }

    /// Extrai a chave z-base-32 de `pkarr:<z32>` ou `did:pkarr:<z32>`.
    pub fn extract_zbase32(identifier: &str) -> Option<&str> {
        let trimmed = identifier.trim();
        trimmed
            .strip_prefix("pkarr:")
            .or_else(|| trimmed.strip_prefix("did:pkarr:"))
    }

    /// Resolve `pkarr:<z32>` ou `did:pkarr:<z32>` verificando o `SignedPacket` e
    /// extraindo o valor `route=<destino>` do registro TXT `_mycelium-pay.<z32>`.
    pub fn resolve_route(&self, identifier: &str) -> Result<String, GatewayError> {
        let z32 = Self::extract_zbase32(identifier)
            .ok_or_else(|| GatewayError::InvalidTarget(identifier.to_string()))?;

        // Valida forma canônica z-base-32 (32 bytes = 52 chars).
        let decoded: [u8; 32] = zbase32::decode::<32>(z32).ok_or_else(|| {
            GatewayError::InvalidTarget(format!("chave PKARR z-base-32 inválida: {z32}"))
        })?;

        let packet = self.packets.get(z32).ok_or_else(|| {
            GatewayError::InvalidTarget(format!("registro PKARR não encontrado para {z32}"))
        })?;

        packet
            .verify()
            .map_err(|e| GatewayError::Crypto(format!("pkarr assinatura inválida: {e}")))?;
        if packet.public_key() != &decoded {
            return Err(GatewayError::Crypto(
                "chave pública do pacote PKARR não bate com o identificador".into(),
            ));
        }

        let records = dns::decode_txt(packet.dns())
            .map_err(|e| GatewayError::Crypto(format!("pkarr dns decode: {e}")))?;
        let expected_name = format!("{PKARR_PAY_LABEL}.{z32}");
        for rec in records {
            if rec.name == expected_name {
                let joined: Vec<u8> = rec.strings.into_iter().flatten().collect();
                let text = String::from_utf8(joined).map_err(|_| {
                    GatewayError::Crypto("registro TXT PKARR não é UTF-8 válido".into())
                })?;
                if let Some(route) = text.strip_prefix("route=") {
                    if !route.trim().is_empty() {
                        return Ok(route.trim().to_string());
                    }
                }
            }
        }

        Err(GatewayError::InvalidTarget(format!(
            "registro TXT {expected_name} sem campo route="
        )))
    }
}
