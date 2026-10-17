//! Transporte P2P real sobre hifas Mycelium (feature `transport-mycelium`).
//!
//! O chamador é responsável por germinar o `HyphaeNode` e chamar `pulse()`
//! periodicamente. Este adaptador é uma ponte síncrona mínima.

#[cfg(feature = "transport-mycelium")]
use mycelium_hyphae::{HyphaeNode, HyphaeError};

#[cfg(feature = "transport-mycelium")]
use crate::error::BankError;
#[cfg(feature = "transport-mycelium")]
use crate::network::{BankMessage, MyceliumTransport};

#[cfg(feature = "transport-mycelium")]
pub struct HyphaeTransport<'a> {
    node: &'a mut HyphaeNode,
}

#[cfg(feature = "transport-mycelium")]
impl<'a> HyphaeTransport<'a> {
    pub fn new(node: &'a mut HyphaeNode) -> Self {
        Self { node }
    }
}

#[cfg(feature = "transport-mycelium")]
impl<'a> MyceliumTransport for HyphaeTransport<'a> {
    fn publish(&mut self, msg: &BankMessage) -> Result<(), BankError> {
        let bytes = serde_json::to_vec(msg).map_err(|e| BankError::Network(e.to_string()))?;
        self.node
            .broadcast_lattice(bytes)
            .map_err(|e: HyphaeError| BankError::Network(e.to_string()))?;
        Ok(())
    }

    fn peers(&mut self) -> Vec<String> {
        self.node
            .links()
            .keys()
            .map(|p| p.to_string())
            .collect()
    }
}
