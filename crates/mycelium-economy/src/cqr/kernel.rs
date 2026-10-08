//! Analytical Mechanics Symplectic Physics Kernel.
//!
//! Classical Phase Space:
//! $$z = (q, p)$$
//!
//! Canonical equations of motion:
//! $$\frac{dz}{dt} = J \nabla H(z)$$
//! where $J = \begin{pmatrix} 0 & I \\ -I & 0 \end{pmatrix}$ is the standard symplectic matrix.
//!
//! Uses symplectic integrators (Velocity Verlet / Leapfrog) that preserve
//! phase space volume (Liouville's theorem) and bound energy drift to $O(\Delta t^2)$
//! with no secular dissipation.

use serde::{Deserialize, Serialize};

/// Point in classical $2N$-dimensional phase space.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseSpacePoint {
    pub q: Vec<f64>,
    pub p: Vec<f64>,
}

impl PhaseSpacePoint {
    pub fn new(q: Vec<f64>, p: Vec<f64>) -> Self {
        assert_eq!(q.len(), p.len(), "q and p dimensions must match");
        Self { q, p }
    }

    pub fn dim(&self) -> usize {
        self.q.len()
    }

    /// Canonical serialization to binary for cryptographic hashing.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.q.len() * 16);
        for &val in &self.q {
            bytes.extend_from_slice(&val.to_le_bytes());
        }
        for &val in &self.p {
            bytes.extend_from_slice(&val.to_le_bytes());
        }
        bytes
    }
}

/// Trait defining a Hamiltonian system with separable kinetic and potential energy:
/// $$H(q, p) = T(p) + V(q)$$
pub trait HamiltonianSystem {
    /// Number of degrees of freedom.
    fn degrees_of_freedom(&self) -> usize;

    /// Kinetic energy $T(p)$.
    fn kinetic_energy(&self, p: &[f64]) -> f64;

    /// Potential energy $V(q)$.
    fn potential_energy(&self, q: &[f64]) -> f64;

    /// Total energy $H(q, p) = T(p) + V(q)$.
    fn total_energy(&self, z: &PhaseSpacePoint) -> f64 {
        self.kinetic_energy(&z.p) + self.potential_energy(&z.q)
    }

    /// Generalized force vector $F_i(q) = -\frac{\partial V}{\partial q_i}$.
    fn compute_forces(&self, q: &[f64]) -> Vec<f64>;

    /// Velocities $\dot{q}_i = \frac{\partial T}{\partial p_i}$.
    fn compute_velocities(&self, p: &[f64]) -> Vec<f64>;
}

/// Symplectic Velocity Verlet integrator.
pub struct VelocityVerlet;

impl VelocityVerlet {
    /// Advances phase space point by a discrete time step `dt` using 2nd-order symplectic integration.
    pub fn step<S: HamiltonianSystem>(
        system: &S,
        state: &mut PhaseSpacePoint,
        dt: f64,
    ) {
        let n = system.degrees_of_freedom();
        assert_eq!(state.dim(), n);

        // 1. Initial forces F(q_t)
        let forces = system.compute_forces(&state.q);

        // 2. Half-step momentum: p(t + dt/2) = p(t) + (dt/2) * F(q_t)
        let mut half_p = vec![0.0; n];
        for (hp, (&pi, &fi)) in half_p.iter_mut().zip(state.p.iter().zip(&forces)) {
            *hp = pi + 0.5 * dt * fi;
        }

        // 3. Full-step position: q(t + dt) = q(t) + dt * v(p(t + dt/2))
        let half_velocities = system.compute_velocities(&half_p);
        for (qi, &vi) in state.q.iter_mut().zip(&half_velocities) {
            *qi += dt * vi;
        }

        // 4. New forces at updated position: F(q_{t+dt})
        let new_forces = system.compute_forces(&state.q);

        // 5. Final half-step momentum: p(t + dt) = p(t + dt/2) + (dt/2) * F(q_{t+dt})
        for (pi, (&hp, &nfi)) in state.p.iter_mut().zip(half_p.iter().zip(&new_forces)) {
            *pi = hp + 0.5 * dt * nfi;
        }
    }
}
