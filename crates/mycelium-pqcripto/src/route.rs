//! Explicit Chameleon privacy-floor policy, not a live network connection.
//!
//! Transport availability MUST come from audited LIVE/MIX data-plane health
//! probes, not user-controlled flags or merely compiling with VEIL.
//! No probe is connected yet, so the all-false default FAILS CLOSED.

use crate::PqCriptoError;
use mycelium_veil::VeilMode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivacyFloor {
    /// Requires the verified three-hop LIVE data path; never choose GEO.
    InteractiveOnion,
    /// Requires a functioning MIX data path with batching and cover traffic.
    DelayedMix,
}

#[derive(Debug, Clone, Default)]
pub struct ObservedTransportState {
    pub kill_switch_active: bool,
    pub post_quantum_link_established: bool,
    pub live_three_hop_data_path_wired: bool,
    pub mix_data_path_wired: bool,
    pub mixing_batches_verified: bool,
    pub cover_traffic_verified: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CamouflageRoutePlan {
    pub mode: VeilMode,
    pub direct_fallback_allowed: bool,
    pub transport_active: bool,
}

pub fn route_plan(
    requirement: PrivacyFloor,
    observed: &ObservedTransportState,
) -> Result<CamouflageRoutePlan, PqCriptoError> {
    if !observed.kill_switch_active || !observed.post_quantum_link_established {
        return Err(PqCriptoError::PrivacyFloor(
            "kill-switch or PQ link not verified",
        ));
    }
    let mode = match requirement {
        PrivacyFloor::InteractiveOnion if observed.live_three_hop_data_path_wired => VeilMode::Veil,
        PrivacyFloor::DelayedMix
            if observed.mix_data_path_wired
                && observed.mixing_batches_verified
                && observed.cover_traffic_verified =>
        {
            VeilMode::Mix
        }
        _ => {
            return Err(PqCriptoError::PrivacyFloor(
                "requested privacy data path unavailable",
            ))
        }
    };
    // A plan is deliberately NOT an active circuit or any proof of anonymity.
    Ok(CamouflageRoutePlan {
        mode,
        direct_fallback_allowed: false,
        transport_active: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_direct_connection_or_degraded_privacy() {
        assert!(route_plan(
            PrivacyFloor::InteractiveOnion,
            &ObservedTransportState::default()
        )
        .is_err());
        let mut s = ObservedTransportState {
            kill_switch_active: true,
            post_quantum_link_established: true,
            live_three_hop_data_path_wired: true,
            ..Default::default()
        };
        let p = route_plan(PrivacyFloor::InteractiveOnion, &s).unwrap();
        assert_eq!(p.mode, VeilMode::Veil);
        assert!(!p.direct_fallback_allowed);
        assert!(!p.transport_active);
        assert!(route_plan(PrivacyFloor::DelayedMix, &s).is_err());
        s.mix_data_path_wired = true;
        s.mixing_batches_verified = true;
        assert!(route_plan(PrivacyFloor::DelayedMix, &s).is_err());
        s.cover_traffic_verified = true;
        assert_eq!(
            route_plan(PrivacyFloor::DelayedMix, &s).unwrap().mode,
            VeilMode::Mix
        );
        s.kill_switch_active = false;
        assert!(route_plan(PrivacyFloor::DelayedMix, &s).is_err());
    }
}
