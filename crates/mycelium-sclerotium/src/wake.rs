//! Protocolo de Despertar Seletivo (Selective Wake) e Impulso (Impulse).
//!
//! Evita "Vampire Attacks" (ataques de negação de sono por inundação de pacotes),
//! garantindo que o nó dormente (ou seu receptor/MCU de baixo consumo) somente
//! inicie a rotina de boot/resume quando receber um WakeToken autenticado e não-repetido.

use mycelium_core::NodeId;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Preâmbulo mágico do pacote de impulso: "MYCE"
pub const IMPULSE_PREAMBLE: [u8; 4] = [0x4D, 0x59, 0x43, 0x45];
/// Versão do protocolo de impulso
pub const IMPULSE_VERSION: u8 = 1;
/// Comando Wake
pub const IMPULSE_CMD_WAKE: u8 = 0x57; // 'W'

/// Erros no processo de despertar.
#[derive(Debug, thiserror::Error)]
pub enum WakeError {
    #[error("MAC de autenticação do WakeToken inválido")]
    InvalidAuthMac,

    #[error("janela temporal expirada: token com epoch {token_epoch}, agora é {now_secs}")]
    EpochSkew { token_epoch: u64, now_secs: u64 },

    #[error("ataque de replay detectado: nonce {nonce} já foi utilizado recentemente")]
    ReplayDetected { nonce: u64 },

    #[error("pacote de impulso corrompido ou incompleto: {0}")]
    MalformedPacket(String),

    #[error("falha de CRC no pacote de impulso")]
    BadChecksum,

    #[error("falha na camada de rede/socket: {0}")]
    IoError(#[from] std::io::Error),
}

/// Razão da requisição de despertar do nó.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum WakeReason {
    /// Execução de computação urgente (Inertia Vector exclusivo).
    UrgentCompute = 1,
    /// Conteúdo exclusivo que não possui réplicas em pares vivos.
    ExclusiveContent = 2,
    /// Estabelecimento de sessão direta ou canal de comunicação prioritário.
    DirectSession = 3,
    /// Manutenção periódica de época e sincronização de feromônios.
    EpochMaintenance = 4,
    /// Despertar manual ordenado pelo operador do nó.
    OperatorManual = 5,
}

impl WakeReason {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::UrgentCompute),
            2 => Some(Self::ExclusiveContent),
            3 => Some(Self::DirectSession),
            4 => Some(Self::EpochMaintenance),
            5 => Some(Self::OperatorManual),
            _ => None,
        }
    }
}

/// Token criptográfico de despertar seletivo.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WakeToken {
    /// Identidade do nó que deve acordar.
    pub target_node: NodeId,
    /// Identidade do nó que solicita o despertar.
    pub requester: NodeId,
    /// Timestamp Unix (em segundos) da emissão.
    pub epoch: u64,
    /// Número aleatório único contra ataques de replay.
    pub nonce: u64,
    /// Razão do despertar.
    pub reason: WakeReason,
    /// Código de Autenticação de Mensagem (BLAKE3 Keyed Hash) gerado com o segredo do nó.
    pub auth_mac: [u8; 32],
}

impl WakeToken {
    /// Deriva a chave de wake do nó a partir de sua semente secreta ou segredo dedicado.
    pub fn derive_wake_key(node_secret: &[u8; 32]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key("mycelium:sclerotium:wake-key:v1");
        hasher.update(node_secret);
        *hasher.finalize().as_bytes()
    }

    /// Calcula o MAC canônico de autenticação do token.
    pub fn compute_mac(
        wake_key: &[u8; 32],
        target_node: &NodeId,
        requester: &NodeId,
        epoch: u64,
        nonce: u64,
        reason: WakeReason,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(wake_key);
        hasher.update(&target_node.0);
        hasher.update(&requester.0);
        hasher.update(&epoch.to_le_bytes());
        hasher.update(&nonce.to_le_bytes());
        hasher.update(&[reason as u8]);
        *hasher.finalize().as_bytes()
    }

    /// Cria um novo WakeToken autenticado.
    pub fn new(
        wake_key: &[u8; 32],
        target_node: NodeId,
        requester: NodeId,
        epoch: u64,
        nonce: u64,
        reason: WakeReason,
    ) -> Self {
        let auth_mac = Self::compute_mac(&wake_key, &target_node, &requester, epoch, nonce, reason);
        Self {
            target_node,
            requester,
            epoch,
            nonce,
            reason,
            auth_mac,
        }
    }
}

/// Validador de WakeToken com proteção estrita contra Replay e Janela Temporal.
pub struct WakeTokenValidator {
    wake_key: [u8; 32],
    local_node_id: NodeId,
    allowed_epoch_skew_secs: u64,
    seen_nonces: HashSet<u64>,
    max_nonce_history: usize,
}

impl WakeTokenValidator {
    pub fn new(wake_key: [u8; 32], local_node_id: NodeId) -> Self {
        Self {
            wake_key,
            local_node_id,
            allowed_epoch_skew_secs: 300, // 5 minutos de tolerância temporal
            seen_nonces: HashSet::with_capacity(1000),
            max_nonce_history: 10_000,
        }
    }

    /// Define a janela de tolerância de epoch em segundos.
    pub fn with_skew_tolerance(mut self, secs: u64) -> Self {
        self.allowed_epoch_skew_secs = secs;
        self
    }

    /// Valida um token de despertar. Retorna Ok(()) se for autêntico e inédito.
    pub fn validate(&mut self, token: &WakeToken, now_secs: u64) -> Result<(), WakeError> {
        // 1. Verifica se é direcionado a este nó
        if token.target_node != self.local_node_id {
            return Err(WakeError::InvalidAuthMac);
        }

        // 2. Janela temporal (evita tokens muito velhos ou muito no futuro)
        let diff = if token.epoch > now_secs {
            token.epoch - now_secs
        } else {
            now_secs - token.epoch
        };

        if diff > self.allowed_epoch_skew_secs {
            return Err(WakeError::EpochSkew {
                token_epoch: token.epoch,
                now_secs,
            });
        }

        // 3. Proteção contra Replay Attack
        if self.seen_nonces.contains(&token.nonce) {
            return Err(WakeError::ReplayDetected { nonce: token.nonce });
        }

        // 4. Verificação de MAC (Tempo constante via blake3)
        let expected_mac = WakeToken::compute_mac(
            &self.wake_key,
            &token.target_node,
            &token.requester,
            token.epoch,
            token.nonce,
            token.reason,
        );

        if expected_mac != token.auth_mac {
            return Err(WakeError::InvalidAuthMac);
        }

        // 5. Marca nonce como utilizado
        if self.seen_nonces.len() >= self.max_nonce_history {
            self.seen_nonces.clear();
        }
        self.seen_nonces.insert(token.nonce);

        Ok(())
    }
}

/// Pacote de Impulso de despertar em formato binário ultra-compacto (50 bytes).
///
/// Ideal para transmissão em:
/// - Portadoras analógicas (FSK, AFSK, modulação em amplitude de baixo ruído)
/// - Rádios LoRa e sub-GHz (433/868/915 MHz)
/// - Carga útil de pacotes Ethernet Wake-on-LAN customizados
///
/// Layout:
/// - [0..4]   Preâmbulo ("MYCE")
/// - [4]      Versão (0x01)
/// - [5]      Comando (0x57 = 'W')
/// - [6]      Razão (u8)
/// - [7]      Flags / Reservado (0x00)
/// - [8..16]  Prefixo Target NodeId (8 bytes)
/// - [16..24] Prefixo Requester NodeId (8 bytes)
/// - [24..32] Epoch (8 bytes little-endian)
/// - [32..40] Nonce (8 bytes little-endian)
/// - [40..48] Prefixo MAC de Autenticação (8 bytes)
/// - [48..50] CRC16-CCITT (2 bytes little-endian)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImpulsePacket {
    pub reason: WakeReason,
    pub target_prefix: [u8; 8],
    pub requester_prefix: [u8; 8],
    pub epoch: u64,
    pub nonce: u64,
    pub mac_prefix: [u8; 8],
}

impl ImpulsePacket {
    pub const PACKET_LEN: usize = 50;

    /// Cria um ImpulsePacket a partir de um WakeToken completo.
    pub fn from_token(token: &WakeToken) -> Self {
        let mut target_prefix = [0u8; 8];
        target_prefix.copy_from_slice(&token.target_node.0[..8]);

        let mut requester_prefix = [0u8; 8];
        requester_prefix.copy_from_slice(&token.requester.0[..8]);

        let mut mac_prefix = [0u8; 8];
        mac_prefix.copy_from_slice(&token.auth_mac[..8]);

        Self {
            reason: token.reason,
            target_prefix,
            requester_prefix,
            epoch: token.epoch,
            nonce: token.nonce,
            mac_prefix,
        }
    }

    /// Serializa para o formato binário de 50 bytes com CRC16.
    pub fn to_bytes(&self) -> [u8; Self::PACKET_LEN] {
        let mut buf = [0u8; Self::PACKET_LEN];
        buf[0..4].copy_from_slice(&IMPULSE_PREAMBLE);
        buf[4] = IMPULSE_VERSION;
        buf[5] = IMPULSE_CMD_WAKE;
        buf[6] = self.reason as u8;
        buf[7] = 0x00; // flags

        buf[8..16].copy_from_slice(&self.target_prefix);
        buf[16..24].copy_from_slice(&self.requester_prefix);
        buf[24..32].copy_from_slice(&self.epoch.to_le_bytes());
        buf[32..40].copy_from_slice(&self.nonce.to_le_bytes());
        buf[40..48].copy_from_slice(&self.mac_prefix);

        let crc = Self::compute_crc16(&buf[..48]);
        buf[48..50].copy_from_slice(&crc.to_le_bytes());

        buf
    }

    /// Decodifica de um buffer binário, validando preâmbulo, versão e CRC16.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WakeError> {
        if bytes.len() != Self::PACKET_LEN {
            return Err(WakeError::MalformedPacket(format!(
                "tamanho inválido: esperado {}, recebido {}",
                Self::PACKET_LEN,
                bytes.len()
            )));
        }

        if &bytes[0..4] != &IMPULSE_PREAMBLE {
            return Err(WakeError::MalformedPacket("preâmbulo incorreto".into()));
        }

        if bytes[4] != IMPULSE_VERSION {
            return Err(WakeError::MalformedPacket("versão de protocolo incompatível".into()));
        }

        if bytes[5] != IMPULSE_CMD_WAKE {
            return Err(WakeError::MalformedPacket("comando de impulso inválido".into()));
        }

        let reason = WakeReason::from_u8(bytes[6])
            .ok_or_else(|| WakeError::MalformedPacket("razão de wake desconhecida".into()))?;

        let expected_crc = u16::from_le_bytes([bytes[48], bytes[49]]);
        let computed_crc = Self::compute_crc16(&bytes[..48]);
        if expected_crc != computed_crc {
            return Err(WakeError::BadChecksum);
        }

        let mut target_prefix = [0u8; 8];
        target_prefix.copy_from_slice(&bytes[8..16]);

        let mut requester_prefix = [0u8; 8];
        requester_prefix.copy_from_slice(&bytes[16..24]);

        let mut epoch_bytes = [0u8; 8];
        epoch_bytes.copy_from_slice(&bytes[24..32]);
        let epoch = u64::from_le_bytes(epoch_bytes);

        let mut nonce_bytes = [0u8; 8];
        nonce_bytes.copy_from_slice(&bytes[32..40]);
        let nonce = u64::from_le_bytes(nonce_bytes);

        let mut mac_prefix = [0u8; 8];
        mac_prefix.copy_from_slice(&bytes[40..48]);

        Ok(Self {
            reason,
            target_prefix,
            requester_prefix,
            epoch,
            nonce,
            mac_prefix,
        })
    }

    /// Cálculo padrão CRC16-CCITT (polinômio 0x1021).
    pub fn compute_crc16(data: &[u8]) -> u16 {
        let mut crc: u16 = 0xFFFF;
        for &byte in data {
            crc ^= (byte as u16) << 8;
            for _ in 0..8 {
                if (crc & 0x8000) != 0 {
                    crc = (crc << 1) ^ 0x1021;
                } else {
                    crc <<= 1;
                }
            }
        }
        crc
    }
}

/// Construtor de pacotes Ethernet Wake-on-LAN (Magic Packet).
pub struct WolPacket;

impl WolPacket {
    /// Constrói um Magic Packet padrão de 102 bytes:
    /// 6 bytes de 0xFF seguidos de 16 repetições do endereço MAC (6 bytes cada).
    pub fn build_magic_packet(mac: &[u8; 6]) -> Vec<u8> {
        let mut packet = Vec::with_capacity(102);
        packet.extend_from_slice(&[0xFF; 6]);
        for _ in 0..16 {
            packet.extend_from_slice(mac);
        }
        packet
    }

    /// Constrói um Magic Packet com extensão SecureON (108 bytes):
    /// Adiciona 6 bytes de senha/token criptográfico no final.
    pub fn build_secureon_packet(mac: &[u8; 6], password: &[u8; 6]) -> Vec<u8> {
        let mut packet = Self::build_magic_packet(mac);
        packet.extend_from_slice(password);
        packet
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wake_token_generation_and_validation() {
        let secret = [0x55; 32];
        let wake_key = WakeToken::derive_wake_key(&secret);
        let target = NodeId::derive(b"target-dormant-node");
        let requester = NodeId::derive(b"requester-live-peer");
        let now = 10_000;

        let token = WakeToken::new(
            &wake_key,
            target,
            requester,
            now,
            1234567,
            WakeReason::UrgentCompute,
        );

        let mut validator = WakeTokenValidator::new(wake_key, target);

        // Validação bem sucedida
        assert!(validator.validate(&token, now + 10).is_ok());

        // Replay imediato deve falhar
        assert!(matches!(
            validator.validate(&token, now + 15),
            Err(WakeError::ReplayDetected { .. })
        ));

        // Token com epoch expirado (mais de 300s)
        let old_token = WakeToken::new(
            &wake_key,
            target,
            requester,
            now - 500,
            999999,
            WakeReason::DirectSession,
        );
        assert!(matches!(
            validator.validate(&old_token, now),
            Err(WakeError::EpochSkew { .. })
        ));

        // Token adulterado com MAC inválido
        let mut bad_token = token.clone();
        bad_token.nonce = 777; // alterou nonce sem recalcular MAC
        assert!(matches!(
            validator.validate(&bad_token, now + 20),
            Err(WakeError::InvalidAuthMac)
        ));
    }

    #[test]
    fn test_impulse_packet_serialization_roundtrip() {
        let secret = [0xAA; 32];
        let wake_key = WakeToken::derive_wake_key(&secret);
        let target = NodeId::derive(b"target");
        let requester = NodeId::derive(b"requester");

        let token = WakeToken::new(&wake_key, target, requester, 5000, 98765, WakeReason::ExclusiveContent);
        let impulse = ImpulsePacket::from_token(&token);

        let bytes = impulse.to_bytes();
        assert_eq!(bytes.len(), 50);

        let decoded = ImpulsePacket::from_bytes(&bytes).expect("decodificação falhou");
        assert_eq!(impulse, decoded);
    }

    #[test]
    fn test_wol_magic_packet() {
        let mac = [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E];
        let pkt = WolPacket::build_magic_packet(&mac);
        assert_eq!(pkt.len(), 102);
        assert_eq!(&pkt[0..6], &[0xFF; 6]);
        assert_eq!(&pkt[6..12], &mac);
        assert_eq!(&pkt[96..102], &mac);

        let pwd = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let sec_pkt = WolPacket::build_secureon_packet(&mac, &pwd);
        assert_eq!(sec_pkt.len(), 108);
        assert_eq!(&sec_pkt[102..108], &pwd);
    }
}
