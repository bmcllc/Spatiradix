//! Physical State Bus — CQR-ME Multiscale Physical State Snapshot.
//!
//! Provides content-addressed, immutable, versioned snapshots across
//! physical layers (geometry, classical phase space, quantum state,
//! statistical ensemble, and stress-energy).
//!
//! Rather than serializing huge raw simulation grids on the wire, the bus
//! tracks cryptographic commitments (BLAKE3) of each component, with
//! canonical domain separation.

use serde::{Deserialize, Serialize};

/// Domain separation string for BLAKE3 hashes on the Physical State Bus.
pub const PHYSICAL_STATE_DOMAIN: &[u8] = b"mycelium:cqr:physical_state:v1";

/// Content-addressed snapshot of a multiscale physical state at a discrete step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhysicalStateSnapshot {
    /// Schema version of the snapshot contract.
    pub schema_version: u32,
    /// Discrete integration or evolution step.
    pub step: u64,
    /// Physical time in natural or dimensionful simulation units.
    pub time: String, // String representation to ensure bitwise JSON portability
    /// BLAKE3 hash of geometry and metric background ($g_{\mu\nu}$, extrinsic curvature).
    pub geometry_hash: String,
    /// BLAKE3 hash of classical phase space coordinates $(q, p)$.
    pub classical_state_hash: String,
    /// BLAKE3 hash of quantum state ($|\psi\rangle$, density matrix $\rho$).
    pub quantum_state_hash: String,
    /// BLAKE3 hash of statistical distribution / coarse-grained ensemble.
    pub statistical_state_hash: String,
    /// BLAKE3 hash of energy-momentum tensor $T_{\mu\nu}$.
    pub stress_energy_hash: String,
    /// BLAKE3 hash of macroscopic and microscopic observables.
    pub observables_hash: String,
}

fn push_str(hasher: &mut blake3::Hasher, s: &str) {
    let bytes = s.as_bytes();
    hasher.update(&(bytes.len() as u32).to_le_bytes());
    hasher.update(bytes);
}

impl PhysicalStateSnapshot {
    /// Computes the canonical state commitment hash of this snapshot.
    ///
    /// Every string component is length-prefixed to prevent concatenation
    /// ambiguity and state commitment collision.
    pub fn state_hash(&self) -> String {
        let mut hasher = blake3::Hasher::new_keyed(&blake3_derive_key(PHYSICAL_STATE_DOMAIN));
        hasher.update(&self.schema_version.to_le_bytes());
        hasher.update(&self.step.to_le_bytes());
        push_str(&mut hasher, &self.time);
        push_str(&mut hasher, &self.geometry_hash);
        push_str(&mut hasher, &self.classical_state_hash);
        push_str(&mut hasher, &self.quantum_state_hash);
        push_str(&mut hasher, &self.statistical_state_hash);
        push_str(&mut hasher, &self.stress_energy_hash);
        push_str(&mut hasher, &self.observables_hash);
        hasher.finalize().to_hex().to_string()
    }
}

/// Helper to derive a 32-byte key from domain bytes.
pub fn blake3_derive_key(domain: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    *hasher.finalize().as_bytes()
}

/// Hashes raw binary payload with domain separation.
pub fn hash_component(component_domain: &[u8], data: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new_keyed(&blake3_derive_key(component_domain));
    hasher.update(data);
    hasher.finalize().to_hex().to_string()
}
