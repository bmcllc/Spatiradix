//! Proxy de Escleródio: Gestão de Leases e Representação de Nós Dormentes.
//!
//! Permite que um nó vivo atue como guardião temporário (proxy) de nós irmãos
//! dormentes, atestando sua existência, indexando réplicas e roteando requisições.

use crate::lease::{GhostLease, LeaseCapability, LeaseError, WakeEndpoint};
use mycelium_core::{ContentId, NodeId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Resposta de status fornecida por um proxy a respeito de um nó dormente.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProxyNodeStatus {
    pub node_id: NodeId,
    pub is_dormant: bool,
    pub lease_valid_until: u64,
    pub capabilities: Vec<LeaseCapability>,
    pub replicated_cids: Vec<ContentId>,
    pub wake_endpoints: Vec<WakeEndpoint>,
}

/// Armazém e gerenciador de GhostLeases em nós guardiões/proxies.
#[derive(Clone, Debug)]
pub struct SclerotiumProxyStore {
    local_node_id: NodeId,
    leases: HashMap<NodeId, GhostLease>,
}

impl SclerotiumProxyStore {
    pub fn new(local_node_id: NodeId) -> Self {
        Self {
            local_node_id,
            leases: HashMap::new(),
        }
    }

    /// Registra uma GhostLease enviada por um nó irmão dormente.
    /// Valida criptografia, validade temporal e autorização do proxy.
    pub fn register_lease(&mut self, lease: GhostLease, now_secs: u64) -> Result<(), LeaseError> {
        lease.verify(now_secs)?;

        // Se a lease especificar proxies explícitos, verifica se somos um deles
        if !lease.authorized_proxies.is_empty() && !lease.authorized_proxies.contains(&self.local_node_id) {
            return Err(LeaseError::UnauthorizedProxy {
                proxy: self.local_node_id,
            });
        }

        self.leases.insert(lease.origin_node_id, lease);
        Ok(())
    }

    /// Consulta o status delegado de um nó. Retorna Some(status) se tivermos uma lease válida.
    pub fn query_node(&self, node_id: &NodeId, now_secs: u64) -> Option<ProxyNodeStatus> {
        let lease = self.leases.get(node_id)?;
        if lease.verify(now_secs).is_err() {
            return None;
        }

        Some(ProxyNodeStatus {
            node_id: lease.origin_node_id,
            is_dormant: true,
            lease_valid_until: lease.valid_until,
            capabilities: lease.capabilities.clone(),
            replicated_cids: lease.replicated_cids.clone(),
            wake_endpoints: lease.wake_endpoints.clone(),
        })
    }

    /// Avalia se podemos receber e armazenar mensagens (DTN Mailbox) para este nó.
    pub fn can_accept_mail_for(&self, node_id: &NodeId, now_secs: u64) -> bool {
        self.leases
            .get(node_id)
            .map(|l| l.allows(&self.local_node_id, LeaseCapability::ReceiveMail, now_secs))
            .unwrap_or(false)
    }

    /// Avalia se podemos responder como anunciante de conteúdo para este nó.
    pub fn can_advertise_for(&self, node_id: &NodeId, now_secs: u64) -> bool {
        self.leases
            .get(node_id)
            .map(|l| l.allows(&self.local_node_id, LeaseCapability::AdvertiseContent, now_secs))
            .unwrap_or(false)
    }

    /// Retorna os endpoints de despertar disponíveis para o nó dormente.
    pub fn wake_endpoints_for(&self, node_id: &NodeId, now_secs: u64) -> Option<Vec<WakeEndpoint>> {
        let lease = self.leases.get(node_id)?;
        if !lease.allows(&self.local_node_id, LeaseCapability::RelayWake, now_secs) {
            return None;
        }
        Some(lease.wake_endpoints.clone())
    }

    /// Remove da memória todas as leases cujo tempo de validade já expirou.
    pub fn prune_expired(&mut self, now_secs: u64) -> usize {
        let initial_len = self.leases.len();
        self.leases.retain(|_, lease| lease.valid_until >= now_secs);
        initial_len - self.leases.len()
    }

    /// Total de nós dormentes atualmente sob custódia deste proxy.
    pub fn active_leases_count(&self) -> usize {
        self.leases.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mycelium_pheromones::Gland;

    #[test]
    fn test_proxy_store_lifecycle() {
        let proxy_gland = Gland::germinate();
        let proxy_id = proxy_gland.node_id();

        let dormant_gland = Gland::germinate();
        let dormant_id = dormant_gland.node_id();

        let mut store = SclerotiumProxyStore::new(proxy_id);
        let now = 1000;

        let cid = ContentId::of(b"spore-plot-xyz");

        let lease = GhostLease::create(
            &dormant_gland,
            1,
            now + 600,
            99,
            vec![proxy_id],
            vec![
                LeaseCapability::AdvertiseContent,
                LeaseCapability::ReceiveMail,
                LeaseCapability::RelayWake,
            ],
            vec![cid],
            vec![WakeEndpoint::EthernetWol {
                mac_address: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            }],
        );

        // Registro bem sucedido
        assert!(store.register_lease(lease, now).is_ok());
        assert_eq!(store.active_leases_count(), 1);

        // Consulta de status
        let status = store.query_node(&dormant_id, now).expect("status esperado");
        assert!(status.is_dormant);
        assert_eq!(status.replicated_cids, vec![cid]);

        // Verificação de permissões
        assert!(store.can_accept_mail_for(&dormant_id, now));
        assert!(store.can_advertise_for(&dormant_id, now));

        let endpoints = store.wake_endpoints_for(&dormant_id, now).unwrap();
        assert_eq!(endpoints.len(), 1);

        // Prune após expiração
        let pruned = store.prune_expired(now + 700);
        assert_eq!(pruned, 1);
        assert_eq!(store.active_leases_count(), 0);
        assert!(store.query_node(&dormant_id, now + 700).is_none());
    }
}
