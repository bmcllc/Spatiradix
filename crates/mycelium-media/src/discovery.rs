//! # mycelium-media: algoritmos intercambiáveis de descoberta
//!
//! No Mycelium Media, nenhum algoritmo central monopoliza a atenção.
//! O usuário escolhe livremente suas lentes de recomendação ou cria a sua própria.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscoveryLens {
    pub id: String,
    pub name: String,
    pub description: String,
    pub weights: HashMap<String, f64>,
}

impl DiscoveryLens {
    pub fn default_symbiosis() -> Self {
        let mut weights = HashMap::new();
        weights.insert("replication_health".to_string(), 0.4);
        weights.insert("reciprocity_score".to_string(), 0.3);
        weights.insert("freshness".to_string(), 0.2);
        weights.insert("peer_trust".to_string(), 0.1);

        Self {
            id: "symbiosis".to_string(),
            name: "Simbiose & Saúde de Réplicas".to_string(),
            description: "Prioriza conteúdos com maior distribuição resiliente e reciprocidade de banda.".to_string(),
            weights,
        }
    }

    pub fn chronological() -> Self {
        let mut weights = HashMap::new();
        weights.insert("published_at".to_string(), 1.0);

        Self {
            id: "chronological".to_string(),
            name: "Cronológico Puro".to_string(),
            description: "Ordem estrita de emissão dos metadados assinados no gossip da rede.".to_string(),
            weights,
        }
    }

    pub fn trust_web() -> Self {
        let mut weights = HashMap::new();
        weights.insert("peer_endorsements".to_string(), 0.7);
        weights.insert("local_affinity".to_string(), 0.3);

        Self {
            id: "trust_web".to_string(),
            name: "Círculo de Confiança".to_string(),
            description: "Baseado em atestações criptográficas e endossos dos nós que você segue.".to_string(),
            weights,
        }
    }
}
