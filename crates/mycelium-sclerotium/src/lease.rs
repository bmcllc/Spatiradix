//! GhostLease: Delegação criptográfica temporária de presença para nós dormentes.
//!
//! Permite que nós vizinhos atuem como "fantasmas autorizados" do nó dormente,
//! respondendo por seus conteúdos, acolhendo mensagens na Mailbox DTN e recebendo
//! requisições de despertar, SEM ter acesso às chaves privadas do nó de origem.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use mycelium_core::{ContentId, NodeId};
use mycelium_pheromones::Gland;
use serde::{Deserialize, Serialize};

/// Erros relacionados a GhostLease.
#[derive(Debug, thiserror::Error)]
pub enum LeaseError {
    #[error("assinatura da lease é inválida")]
    BadSignature,

    #[error("lease expirada: válida até {valid_until}, agora é {now}")]
    Expired { valid_until: u64, now: u64 },

    #[error("chave pública inconsistente com NodeId de origem")]
    IdentityMismatch,

    #[error("proxy {proxy} não autorizado nesta lease")]
    UnauthorizedProxy { proxy: NodeId },

    #[error("capacidade {0:?} não conferida nesta lease")]
    MissingCapability(LeaseCapability),

    #[error("erro de decodificação: {0}")]
    Codec(String),
}

/// Capacidades delegadas por uma GhostLease aos proxies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseCapability {
    /// Anunciar presença lógica e localização de réplicas de CIDs do nó.
    AdvertiseContent,

    /// Acolher mensagens e pacotes DTN destinados ao nó na Mailbox local.
    ReceiveMail,

    /// Enfileirar tarefas de computação e vetores de execução para o nó.
    QueueJobs,

    /// Encaminhar ou disparar impulsos de wake (despertar seletivo).
    RelayWake,

    /// Acesso de assinante ao conteúdo premium do nó de origem (periodicidade da assinatura
    /// é imposta por `valid_until`; a capacidade em si é permanente dentro da lease).
    Subscriber,
}

/// Endpoint físico ou lógico para transmissão do impulso de despertar.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WakeEndpoint {
    /// Wake-on-LAN Ethernet tradicional (endereço MAC: 6 bytes).
    EthernetWol { mac_address: [u8; 6] },

    /// Rádio Sub-GHz / LoRa (canal, frequência em Hz, nó de rádio id).
    SubGhzRadio {
        frequency_hz: u32,
        mesh_id: u32,
        radio_node_id: u64,
    },

    /// Dispositivo Serial/UART Sidecar (ex: ESP32-C3 ou RP2040 conectado na máquina).
    McuSidecar { device_path: String, baud_rate: u32 },

    /// Endereço multiaddr libp2p de proxy intermediário ou rede local.
    NetworkRelay { multiaddr: String },
}

/// GhostLease assinada pelo nó de origem.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GhostLease {
    /// Identidade lógica do nó de origem (BLAKE3 da chave pública).
    pub origin_node_id: NodeId,

    /// Chave pública ed25519 do nó de origem (32 bytes).
    pub origin_pubkey: [u8; 32],

    /// Época de emissão da lease.
    pub epoch: u64,

    /// Validade máxima da lease (timestamp Unix em segundos).
    pub valid_until: u64,

    /// Nonce aleatório para evitar colisões e replays de lease.
    pub nonce: u64,

    /// Lista opcional de proxies autorizados. Se vazia, qualquer par com capacidade
    /// suficiente pode acolher a lease dentro do quórum de vizinhos.
    pub authorized_proxies: Vec<NodeId>,

    /// Conjunto de capacidades conferidas pela lease.
    pub capabilities: Vec<LeaseCapability>,

    /// CIDs de conteúdos e esporos pertencentes a este nó que estão replicados.
    pub replicated_cids: Vec<ContentId>,

    /// Endpoints de wake para contato via Ghost Carrier.
    pub wake_endpoints: Vec<WakeEndpoint>,

    /// Assinatura ed25519 produzida pela Gland do nó de origem sobre o payload canônico.
    pub signature: Vec<u8>,
}

impl GhostLease {
    /// Produz o payload canônico em bytes para assinatura e verificação.
    pub fn canonical_payload(
        origin_node_id: &NodeId,
        origin_pubkey: &[u8; 32],
        epoch: u64,
        valid_until: u64,
        nonce: u64,
        authorized_proxies: &[NodeId],
        capabilities: &[LeaseCapability],
        replicated_cids: &[ContentId],
        wake_endpoints: &[WakeEndpoint],
    ) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"mycelium:ghost-lease:v1\n");
        hasher.update(&origin_node_id.0);
        hasher.update(origin_pubkey);
        hasher.update(&epoch.to_le_bytes());
        hasher.update(&valid_until.to_le_bytes());
        hasher.update(&nonce.to_le_bytes());

        // Proxies autorizados
        hasher.update(&(authorized_proxies.len() as u64).to_le_bytes());
        for p in authorized_proxies {
            hasher.update(&p.0);
        }

        // Capacidades ordenadas
        let mut caps = capabilities.to_vec();
        caps.sort_by_key(|c| match c {
            LeaseCapability::AdvertiseContent => 0,
            LeaseCapability::ReceiveMail => 1,
            LeaseCapability::QueueJobs => 2,
            LeaseCapability::RelayWake => 3,
            LeaseCapability::Subscriber => 4,
        });
        hasher.update(&(caps.len() as u64).to_le_bytes());
        for c in &caps {
            let cap_id: u8 = match c {
                LeaseCapability::AdvertiseContent => 1,
                LeaseCapability::ReceiveMail => 2,
                LeaseCapability::QueueJobs => 3,
                LeaseCapability::RelayWake => 4,
                LeaseCapability::Subscriber => 5,
            };
            hasher.update(&[cap_id]);
        }

        // CIDs replicados
        hasher.update(&(replicated_cids.len() as u64).to_le_bytes());
        for cid in replicated_cids {
            hasher.update(&cid.0);
        }

        // Endpoints de wake codificados
        let endpoints_json = serde_json::to_vec(wake_endpoints).unwrap_or_default();
        hasher.update(&(endpoints_json.len() as u64).to_le_bytes());
        hasher.update(&endpoints_json);

        hasher.finalize().as_bytes().to_vec()
    }

    /// Emite e assina uma nova GhostLease a partir da Gland do nó.
    pub fn create(
        gland: &Gland,
        epoch: u64,
        valid_until: u64,
        nonce: u64,
        authorized_proxies: Vec<NodeId>,
        capabilities: Vec<LeaseCapability>,
        replicated_cids: Vec<ContentId>,
        wake_endpoints: Vec<WakeEndpoint>,
    ) -> Self {
        let origin_node_id = gland.node_id();
        let pubkey_bytes = gland.verifying_key().to_bytes();

        let payload = Self::canonical_payload(
            &origin_node_id,
            &pubkey_bytes,
            epoch,
            valid_until,
            nonce,
            &authorized_proxies,
            &capabilities,
            &replicated_cids,
            &wake_endpoints,
        );

        let signature = gland.sign_bytes(&payload);

        Self {
            origin_node_id,
            origin_pubkey: pubkey_bytes,
            epoch,
            valid_until,
            nonce,
            authorized_proxies,
            capabilities,
            replicated_cids,
            wake_endpoints,
            signature,
        }
    }

    /// Verifica criptograficamente a validade e a integridade da GhostLease.
    pub fn verify(&self, now_secs: u64) -> Result<(), LeaseError> {
        // 1. Verifica consistência entre pubkey e origin_node_id
        let derived = NodeId::derive(&self.origin_pubkey);
        if derived != self.origin_node_id {
            return Err(LeaseError::IdentityMismatch);
        }

        // 2. Verifica se a lease já expirou
        if now_secs > self.valid_until {
            return Err(LeaseError::Expired {
                valid_until: self.valid_until,
                now: now_secs,
            });
        }

        // 3. Verifica assinatura ed25519
        let verifying_key = VerifyingKey::from_bytes(&self.origin_pubkey)
            .map_err(|_| LeaseError::BadSignature)?;

        let sig_bytes: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| LeaseError::BadSignature)?;
        let signature = Signature::from_bytes(&sig_bytes);

        let payload = Self::canonical_payload(
            &self.origin_node_id,
            &self.origin_pubkey,
            self.epoch,
            self.valid_until,
            self.nonce,
            &self.authorized_proxies,
            &self.capabilities,
            &self.replicated_cids,
            &self.wake_endpoints,
        );

        verifying_key
            .verify(&payload, &signature)
            .map_err(|_| LeaseError::BadSignature)?;

        Ok(())
    }

    /// Avalia se um proxy específico possui permissão para exercer uma dada capacidade.
    pub fn allows(&self, proxy: &NodeId, capability: LeaseCapability, now_secs: u64) -> bool {
        if self.verify(now_secs).is_err() {
            return false;
        }

        if !self.authorized_proxies.is_empty() && !self.authorized_proxies.contains(proxy) {
            return false;
        }

        self.capabilities.contains(&capability)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ghost_lease_creation_and_verification() {
        let gland = Gland::germinate();
        let node_id = gland.node_id();
        let now = 1000;
        let valid_until = 2000;

        let proxy = NodeId::derive(b"proxy-peer-1");

        let lease = GhostLease::create(
            &gland,
            1,
            valid_until,
            42,
            vec![proxy],
            vec![LeaseCapability::AdvertiseContent, LeaseCapability::ReceiveMail],
            vec![],
            vec![WakeEndpoint::EthernetWol {
                mac_address: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            }],
        );

        assert_eq!(lease.origin_node_id, node_id);
        assert!(lease.verify(now).is_ok());

        // Proxy autorizado com capacidade autorizada
        assert!(lease.allows(&proxy, LeaseCapability::AdvertiseContent, now));
        assert!(lease.allows(&proxy, LeaseCapability::ReceiveMail, now));

        // Capacidade não delegada
        assert!(!lease.allows(&proxy, LeaseCapability::QueueJobs, now));

        // Proxy não autorizado
        let unauthorized = NodeId::derive(b"random-stranger");
        assert!(!lease.allows(&unauthorized, LeaseCapability::AdvertiseContent, now));

        // Após expirar
        assert!(lease.verify(valid_until + 1).is_err());
        assert!(!lease.allows(&proxy, LeaseCapability::AdvertiseContent, valid_until + 1));
    }

    #[test]
    fn test_subscriber_capability_is_not_granted_by_ghost_leases() {
        let gland = Gland::germinate();
        let now = 1000;
        let subscriber = NodeId::derive(b"subscriber-1");

        // Lease de assinatura: emitida para um assinante específico, com capacidade única.
        let sub_lease = GhostLease::create(
            &gland,
            1,
            2000,
            7,
            vec![subscriber],
            vec![LeaseCapability::Subscriber],
            vec![],
            vec![],
        );
        assert!(sub_lease.verify(now).is_ok());
        assert!(sub_lease.allows(&subscriber, LeaseCapability::Subscriber, now));
        assert!(!sub_lease.allows(&subscriber, LeaseCapability::AdvertiseContent, now));
        // Após o fim do período da assinatura, a capacidade de assinante cai junto com a lease.
        assert!(!sub_lease.allows(&subscriber, LeaseCapability::Subscriber, 2001));

        // Uma lease de dormência (GhostCarrier) não confere acesso de assinante.
        let ghost_lease = GhostLease::create(
            &gland,
            1,
            2000,
            8,
            vec![subscriber],
            vec![
                LeaseCapability::AdvertiseContent,
                LeaseCapability::ReceiveMail,
                LeaseCapability::RelayWake,
            ],
            vec![],
            vec![],
        );
        assert!(ghost_lease.verify(now).is_ok());
        assert!(!ghost_lease.allows(&subscriber, LeaseCapability::Subscriber, now));
    }

    #[test]
    fn test_tampered_ghost_lease_fails() {
        let gland = Gland::germinate();
        let now = 1000;
        let mut lease = GhostLease::create(
            &gland,
            1,
            2000,
            42,
            vec![],
            vec![LeaseCapability::AdvertiseContent],
            vec![],
            vec![],
        );

        // Adiciona uma capacidade não assinada
        lease.capabilities.push(LeaseCapability::RelayWake);
        assert!(lease.verify(now).is_err());
    }
}
