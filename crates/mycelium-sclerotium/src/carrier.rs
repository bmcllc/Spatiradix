//! Ghost Carrier: Camada física/portadora de sinais sintéticos de baixo consumo.
//!
//! Abstrai os meios físicos pelos quais impulsos de despertar e presença basal
//! são transmitidos (Ethernet WoL, Rádio Sub-GHz / LoRa, MCU serial sidecar e virtual).

use crate::lease::WakeEndpoint;
use crate::wake::{ImpulsePacket, WolPacket};
use std::net::UdpSocket;
use std::sync::{Arc, Mutex};

/// Erros da camada de Ghost Carrier.
#[derive(Debug, thiserror::Error)]
pub enum CarrierError {
    #[error("falha de I/O na portadora: {0}")]
    Io(#[from] std::io::Error),

    #[error("endpoint incompatível com esta portadora")]
    IncompatibleEndpoint,

    #[error("dispositivo serial ou rádio indisponível: {0}")]
    DeviceUnavailable(String),

    #[error("erro interno na portadora: {0}")]
    Internal(String),
}

/// Tipo fisiológico da portadora.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CarrierType {
    /// Rede cabeada Ethernet (Wake-on-LAN)
    Ethernet,
    /// Rádio de ultra-baixo consumo / LoRa / Sub-GHz
    SubGhzRadio,
    /// Microcontrolador auxiliar conectado via barramento Serial/UART
    McuSidecar,
    /// Portadora em memória (testes e simulações)
    Virtual,
}

/// Trait implementado por qualquer transportador de Ghost Carrier.
pub trait GhostCarrier: Send + Sync {
    /// Nome descritivo da portadora (ex: "ethernet-wol", "esp32-lora-uart").
    fn name(&self) -> &'static str;

    /// Tipo fisiológico da portadora.
    fn carrier_type(&self) -> CarrierType;

    /// Envia um pacote de impulso para o endpoint do nó de destino.
    fn send_impulse(
        &self,
        endpoint: &WakeEndpoint,
        impulse: &ImpulsePacket,
    ) -> Result<(), CarrierError>;

    /// Envia um pacote Wake-on-LAN Ethernet padrão (opcionalmente com SecureON).
    fn send_wol(
        &self,
        mac: &[u8; 6],
        secureon_password: Option<&[u8; 6]>,
    ) -> Result<(), CarrierError>;
}

/// Implementação de Ghost Carrier via Ethernet UDP Broadcast (WoL / WoWLAN).
pub struct EthernetCarrier {
    broadcast_port: u16,
}

impl Default for EthernetCarrier {
    fn default() -> Self {
        Self::new(9)
    }
}

impl EthernetCarrier {
    pub fn new(broadcast_port: u16) -> Self {
        Self { broadcast_port }
    }

    /// Tenta ler os endereços MAC de interfaces de rede físicas locais no Linux.
    pub fn detect_local_macs() -> Vec<([u8; 6], String)> {
        let mut macs = Vec::new();
        let net_dir = std::path::Path::new("/sys/class/net");
        if let Ok(entries) = std::fs::read_dir(net_dir) {
            for entry in entries.flatten() {
                let iface_name = entry.file_name().to_string_lossy().to_string();
                if iface_name == "lo" {
                    continue;
                }
                let addr_file = entry.path().join("address");
                if let Ok(content) = std::fs::read_to_string(addr_file) {
                    let cleaned = content.trim();
                    let parts: Vec<&str> = cleaned.split(':').collect();
                    if parts.len() == 6 {
                        let mut bytes = [0u8; 6];
                        let mut ok = true;
                        for (i, p) in parts.iter().enumerate() {
                            if let Ok(b) = u8::from_str_radix(p, 16) {
                                bytes[i] = b;
                            } else {
                                ok = false;
                                break;
                            }
                        }
                        if ok && bytes != [0u8; 6] {
                            macs.push((bytes, iface_name));
                        }
                    }
                }
            }
        }
        macs
    }
}

impl GhostCarrier for EthernetCarrier {
    fn name(&self) -> &'static str {
        "ethernet-wol"
    }

    fn carrier_type(&self) -> CarrierType {
        CarrierType::Ethernet
    }

    fn send_impulse(
        &self,
        endpoint: &WakeEndpoint,
        impulse: &ImpulsePacket,
    ) -> Result<(), CarrierError> {
        match endpoint {
            WakeEndpoint::EthernetWol { mac_address } => {
                // No caso Ethernet, enviamos o Magic Packet e em seguida o payload do Impulse
                let pwd = &impulse.mac_prefix[..6];
                let mut pwd_arr = [0u8; 6];
                pwd_arr.copy_from_slice(pwd);

                self.send_wol(mac_address, Some(&pwd_arr))?;

                // Também enviamos os 50 bytes do ImpulsePacket em UDP broadcast
                let socket = UdpSocket::bind("0.0.0.0:0")?;
                socket.set_broadcast(true)?;
                let dest = format!("255.255.255.255:{}", self.broadcast_port);
                let impulse_bytes = impulse.to_bytes();
                socket.send_to(&impulse_bytes, &dest)?;

                Ok(())
            }
            _ => Err(CarrierError::IncompatibleEndpoint),
        }
    }

    fn send_wol(
        &self,
        mac: &[u8; 6],
        secureon_password: Option<&[u8; 6]>,
    ) -> Result<(), CarrierError> {
        let payload = match secureon_password {
            Some(pwd) => WolPacket::build_secureon_packet(mac, pwd),
            None => WolPacket::build_magic_packet(mac),
        };

        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_broadcast(true)?;
        let dest = format!("255.255.255.255:{}", self.broadcast_port);
        socket.send_to(&payload, &dest)?;

        Ok(())
    }
}

/// Portadora Virtual em memória para testes, simulação e redes locais.
#[derive(Default, Clone)]
pub struct VirtualCarrier {
    sent_impulses: Arc<Mutex<Vec<(WakeEndpoint, ImpulsePacket)>>>,
    sent_wol_packets: Arc<Mutex<Vec<([u8; 6], Option<[u8; 6]>)>>>,
}

impl VirtualCarrier {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn last_impulse(&self) -> Option<(WakeEndpoint, ImpulsePacket)> {
        self.sent_impulses.lock().unwrap().last().cloned()
    }

    pub fn last_wol(&self) -> Option<([u8; 6], Option<[u8; 6]>)> {
        self.sent_wol_packets.lock().unwrap().last().cloned()
    }

    pub fn total_impulses(&self) -> usize {
        self.sent_impulses.lock().unwrap().len()
    }
}

impl GhostCarrier for VirtualCarrier {
    fn name(&self) -> &'static str {
        "virtual-carrier"
    }

    fn carrier_type(&self) -> CarrierType {
        CarrierType::Virtual
    }

    fn send_impulse(
        &self,
        endpoint: &WakeEndpoint,
        impulse: &ImpulsePacket,
    ) -> Result<(), CarrierError> {
        self.sent_impulses
            .lock()
            .unwrap()
            .push((endpoint.clone(), impulse.clone()));
        Ok(())
    }

    fn send_wol(
        &self,
        mac: &[u8; 6],
        secureon_password: Option<&[u8; 6]>,
    ) -> Result<(), CarrierError> {
        self.sent_wol_packets
            .lock()
            .unwrap()
            .push((*mac, secureon_password.copied()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wake::WakeReason;

    #[test]
    fn test_virtual_carrier_dispatches_impulses() {
        let carrier = VirtualCarrier::new();
        let endpoint = WakeEndpoint::EthernetWol {
            mac_address: [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC],
        };

        let impulse = ImpulsePacket {
            reason: WakeReason::UrgentCompute,
            target_prefix: [1; 8],
            requester_prefix: [2; 8],
            epoch: 1000,
            nonce: 42,
            mac_prefix: [9; 8],
        };

        assert!(carrier.send_impulse(&endpoint, &impulse).is_ok());
        assert_eq!(carrier.total_impulses(), 1);

        let (ep, imp) = carrier.last_impulse().unwrap();
        assert_eq!(ep, endpoint);
        assert_eq!(imp, impulse);
    }
}
