//! # mycelium-sclerotium
//!
//! Protocolo de Escleródio (Sclerotium Protocol) e Portadora Fantasma (Ghost Carrier)
//! para o substrato Spatiradix.
//!
//! Permite que nós entrem em dormência profunda (economia extrema de energia e hardware)
//! mantendo sua presença lógica por meio de:
//! 1. **GhostLease**: Delegação criptográfica temporária a proxies vizinhos (sem chave privada).
//! 2. **WakeToken & Impulse**: Despertar seletivo anti-DoS com tokens autenticados e proteção contra replay.
//! 3. **Ghost Carrier**: Portadoras de baixa energia (Ethernet WoL / WoWLAN, Sub-GHz RF / LoRa, MCU sidecar).
//! 4. **Máquina de Estados Biológica**: Transições `Sprouting -> Alive <-> Dormant <-> Ghost -> Dead`.

pub mod carrier;
pub mod lease;
pub mod proxy;
pub mod state;
pub mod wake;

pub use carrier::{CarrierError, CarrierType, EthernetCarrier, GhostCarrier, VirtualCarrier};
pub use lease::{GhostLease, LeaseCapability, LeaseError, WakeEndpoint};
pub use proxy::{ProxyNodeStatus, SclerotiumProxyStore};
pub use state::NodeLifecycleState;
pub use wake::{
    ImpulsePacket, WakeError, WakeReason, WakeToken, WakeTokenValidator, WolPacket,
    IMPULSE_CMD_WAKE, IMPULSE_PREAMBLE, IMPULSE_VERSION,
};
