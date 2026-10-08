//! Máquina de estados do nó no substrato Mycelium.
//!
//! Representa a transição biológica entre nó ativo, dormente (escleródio),
//! fantasma (delegado por quórum) e decomposto/morto.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Estados biológicos de ciclo de vida de um nó.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeLifecycleState {
    /// Brotando: processo inicializando, gerando/carregando chaves, estabelecendo hifas.
    Sprouting,

    /// Vivo (Fruiting): CPU/GPU ligadas, libp2p completo, servindo tráfego e computação.
    Alive,

    /// Dormente (Sclerotium): CPU principal dormindo (suspend-to-RAM/disk),
    /// wake receiver ativo na PHY de baixo consumo, escutando impulsos legítimos.
    Dormant,

    /// Fantasma (Ghost): máquina sem comunicação física direta (desligada/fora de alcance);
    /// identidade lógica mantida temporariamente por um quórum de proxies via GhostLease.
    Ghost,

    /// Morto (Dead/Decomposed): GhostLease expirou sem renovação, feromônio evaporou,
    /// recursos devolvidos ao substrato.
    Dead,
}

impl NodeLifecycleState {
    /// Retorna `true` se o nó puder processar computação ativamente agora.
    pub fn is_active_compute(&self) -> bool {
        matches!(self, Self::Alive)
    }

    /// Retorna `true` se o nó possui presença lógica (direta ou por delegação).
    pub fn is_logically_present(&self) -> bool {
        matches!(self, Self::Alive | Self::Dormant | Self::Ghost)
    }

    /// Retorna `true` se o nó puder ser acordado fisicamente por um impulso de rádio/rede.
    pub fn is_wakeable(&self) -> bool {
        matches!(self, Self::Dormant)
    }

    /// Valida se a transição entre estados é biologicamente plausível.
    pub fn can_transition_to(&self, next: NodeLifecycleState) -> bool {
        match (self, next) {
            // Brotando pode virar Vivo ou falhar para Morto
            (Self::Sprouting, Self::Alive) => true,
            (Self::Sprouting, Self::Dead) => true,

            // Vivo pode hibernar (Dormente), desligar delegando (Ghost) ou morrer
            (Self::Alive, Self::Dormant) => true,
            (Self::Alive, Self::Ghost) => true,
            (Self::Alive, Self::Dead) => true,

            // Dormente pode acordar (Vivo), perder energia de standby (Ghost) ou expirar (Dead)
            (Self::Dormant, Self::Alive) => true,
            (Self::Dormant, Self::Ghost) => true,
            (Self::Dormant, Self::Dead) => true,

            // Fantasma pode ser religado fisicamente (Vivo/Sprouting) ou expirar definitivamente (Dead)
            (Self::Ghost, Self::Sprouting) => true,
            (Self::Ghost, Self::Alive) => true,
            (Self::Ghost, Self::Dead) => true,

            // Morto pode apenas ser re-germinado do zero (Sprouting)
            (Self::Dead, Self::Sprouting) => true,

            // Mesma transição idempotente
            (a, b) if *a == b => true,

            _ => false,
        }
    }
}

impl fmt::Display for NodeLifecycleState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Sprouting => "sprouting",
            Self::Alive => "alive",
            Self::Dormant => "dormant",
            Self::Ghost => "ghost",
            Self::Dead => "dead",
        };
        write!(f, "{s}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_transitions() {
        assert!(NodeLifecycleState::Alive.can_transition_to(NodeLifecycleState::Dormant));
        assert!(NodeLifecycleState::Dormant.can_transition_to(NodeLifecycleState::Alive));
        assert!(NodeLifecycleState::Dormant.can_transition_to(NodeLifecycleState::Ghost));
        assert!(NodeLifecycleState::Ghost.can_transition_to(NodeLifecycleState::Dead));
        assert!(NodeLifecycleState::Ghost.can_transition_to(NodeLifecycleState::Alive));
    }

    #[test]
    fn test_invalid_transitions() {
        assert!(!NodeLifecycleState::Sprouting.can_transition_to(NodeLifecycleState::Dormant));
        assert!(!NodeLifecycleState::Dead.can_transition_to(NodeLifecycleState::Dormant));
    }
}
