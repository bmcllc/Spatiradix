//! CUPP: Cameon Universal Purchasing Power — OFFLINE coverage admission model.
//!
//! This is a protocol for *proposed* financing of payer-directed purchases.
//! One Cameon can authorize different invoice values, but only a treasury
//! containing sufficient REAL spendable destination currency can finance them.
//!
//! Inspired by the user-supplied QVP-2/ARQ risk architecture: point-in-time
//! independent sources, liquidity-aware execution, costs, risk limits and kill
//! switches. QVP rank is NOT used as proof of money or guaranteed returns.
//!
//! No bank balances, redemption, token debits, provider authorization,
//! tax obligation, payment finality or fraud protection are verified here.
//! Simulation snapshots supplied by the caller MUST NOT be treated as proof.

use crate::chameleon::Destination;
use crate::payer_checkout::{
    prepare_payer_checkout, PayerMandate, PreparedPayerCheckout, ReportedFunding,
};
use crate::PqCriptoError;

pub const MAX_OBSERVATION_AGE_SECS: u64 = 60;
pub const MIN_INDEPENDENT_SOURCES: u8 = 2;

/// External observation only. Real bank/PSP adapters still must authenticate
/// balances and guarantee that a reservation cannot be double-spent.
#[derive(Clone, Debug)]
pub struct TreasuryObservation {
    pub destination: Destination,
    /// Actually available amount claimed by the provider, in minor units.
    pub reported_liquid_minor: u128,
    /// Existing holds and already-committed payments, same currency/units.
    pub reported_reserved_minor: u128,
    /// Timestamp from an identified observation provider, not current wall time.
    pub observed_at: u64,
    /// The two sources must be genuinely independent, not duplicated APIs.
    pub independent_sources: u8,
}

/// Risk checks only; no algorithm can turn them into certified money.
/// Use explicit basis-point values (1 bps = 0.01%), no floating point.
#[derive(Clone, Copy, Debug)]
pub struct ArqRiskSignals {
    /// Is the strategy exposed to assets with insufficient execution liquidity?
    pub estimated_slippage_bps: u16,
    pub maximum_acceptable_slippage_bps: u16,
    /// Conservative outlay budget for this payout relative to available capital.
    pub projected_drawdown_bps: u16,
    pub maximum_drawdown_bps: u16,
    /// VaR is a risk estimate, NOT a reserve guarantee.
    pub estimated_var_95_bps: u16,
    pub maximum_var_95_bps: u16,
    /// From QVP-2: recalibrate or suspend on >30% rank-IC deterioration for
    /// two consecutive months. This is a flag, not a live data computation.
    pub rank_ic_drift_bps: u16,
    pub consecutive_drift_months: u8,
    /// Must be asserted from trusted risk and event-monitoring feeds.
    pub hack_or_exploit: bool,
    pub depeg_or_consensus_failure: bool,
    pub regulatory_stop: bool,
    pub liquidity_crisis: bool,
}

impl ArqRiskSignals {
    pub fn conservative_demo() -> Self {
        Self {
            estimated_slippage_bps: 0,
            maximum_acceptable_slippage_bps: 100,
            projected_drawdown_bps: 0,
            maximum_drawdown_bps: 300,
            estimated_var_95_bps: 0,
            maximum_var_95_bps: 300,
            rank_ic_drift_bps: 0,
            consecutive_drift_months: 0,
            hack_or_exploit: false,
            depeg_or_consensus_failure: false,
            regulatory_stop: false,
            liquidity_crisis: false,
        }
    }

    fn validate(&self) -> Result<(), PqCriptoError> {
        if self.estimated_slippage_bps > 10_000
            || self.maximum_acceptable_slippage_bps > 10_000
            || self.projected_drawdown_bps > 10_000
            || self.maximum_drawdown_bps > 10_000
            || self.estimated_var_95_bps > 10_000
            || self.maximum_var_95_bps > 10_000
            || self.rank_ic_drift_bps > 10_000
        {
            return Err(PqCriptoError::Price("ARQ risk basis points out of range"));
        }
        if self.hack_or_exploit
            || self.depeg_or_consensus_failure
            || self.regulatory_stop
            || self.liquidity_crisis
        {
            return Err(PqCriptoError::Price("ARQ treasury kill switch active"));
        }
        if self.estimated_slippage_bps > self.maximum_acceptable_slippage_bps
            || self.projected_drawdown_bps > self.maximum_drawdown_bps
            || self.estimated_var_95_bps > self.maximum_var_95_bps
        {
            return Err(PqCriptoError::Price("ARQ execution/risk limits exceeded"));
        }
        if self.rank_ic_drift_bps > 3_000 && self.consecutive_drift_months >= 2 {
            return Err(PqCriptoError::Price("ARQ persistent model drift"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct ProposedCameonCoverage {
    pub checkout: PreparedPayerCheckout,
    /// The delta a real funding adapter would have to reserve atomically.
    pub reservation_required_minor: u128,
    /// Exactly the seller's invoice currency; no cross-currency netting.
    pub reservation_asset: Destination,
    /// True always: only a planning result, not a bank hold.
    pub funding_reservation_pending: bool,
}

/// Preliminary funding gate. Does not acquire or transfer money.
/// Caller-supplied snapshots and risk booleans are NOT independently verified.
/// Never expose a UI state "paid", "covered", or "guaranteed" from this result.
#[allow(clippy::too_many_arguments)]
pub fn prepare_cupp_coverage(
    mandate: &PayerMandate,
    chain: &str,
    expected_payer_key: &[u8],
    expected_recipient: &[u8; 32],
    expected_invoice: &[u8; 32],
    now: u64,
    reported_cameon_balance_micros: u64,
    funding: &TreasuryObservation,
    risk: &ArqRiskSignals,
) -> Result<ProposedCameonCoverage, PqCriptoError> {
    risk.validate()?;
    if funding.destination != mandate.destination {
        return Err(PqCriptoError::Price(
            "treasury asset differs from seller invoice",
        ));
    }
    if funding.independent_sources < MIN_INDEPENDENT_SOURCES
        || now < funding.observed_at
        || now - funding.observed_at > MAX_OBSERVATION_AGE_SECS
    {
        return Err(PqCriptoError::Price(
            "unverified or stale treasury observation",
        ));
    }
    if funding.reported_reserved_minor > funding.reported_liquid_minor {
        return Err(PqCriptoError::Price("treasury already overcommitted"));
    }
    let checkout = prepare_payer_checkout(
        mandate,
        chain,
        expected_payer_key,
        expected_recipient,
        expected_invoice,
        now,
        reported_cameon_balance_micros,
        ReportedFunding {
            liquid_minor: funding.reported_liquid_minor,
            precommitted_minor: funding.reported_reserved_minor,
        },
    )?;
    Ok(ProposedCameonCoverage {
        reservation_required_minor: checkout.reported_funding_required_minor,
        reservation_asset: checkout.destination.clone(),
        funding_reservation_pending: true,
        checkout,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chameleon::PaymentRail;
    use crate::payer_checkout::ONE_CAMEON_MICROS;

    fn harness() {
        let seed = [29; 32];
        let brl = Destination::fiat("BRL", 2).unwrap();
        // A bread costs 1.00 BRL and includes 0.05 BRL taxes; the treasury
        // must fund 1.00 + 0.02 fee, not 1.07 (no double-count of included tax).
        let mandate = PayerMandate::sign(
            &seed,
            "cameon-testnet",
            [1; 32],
            [2; 32],
            ONE_CAMEON_MICROS,
            brl.clone(),
            PaymentRail::Pix,
            100,
            5,
            0,
            2,
            100,
            200,
        )
        .unwrap();
        let funding = TreasuryObservation {
            destination: brl,
            reported_liquid_minor: 102,
            reported_reserved_minor: 0,
            observed_at: 102,
            independent_sources: 2,
        };
        let risk = ArqRiskSignals::conservative_demo();
        let plan = prepare_cupp_coverage(
            &mandate,
            "cameon-testnet",
            &mandate.payer_public_mldsa87,
            &[1; 32],
            &[2; 32],
            103,
            3 * ONE_CAMEON_MICROS,
            &funding,
            &risk,
        )
        .unwrap();
        assert_eq!(plan.checkout.seller_receive_minor, 100);
        assert_eq!(
            plan.checkout.remaining_cameon_micros_if_spent,
            2 * ONE_CAMEON_MICROS
        );
        assert_eq!(plan.reservation_required_minor, 102);
        assert!(plan.funding_reservation_pending);
        assert!(!plan.checkout.settled);

        // Same one-Cameon spend can propose a USD 25.00 checkout, but only
        // if the external USD funding is at least the exact seller payout.
        let usd = Destination::fiat("USD", 2).unwrap();
        let car = PayerMandate::sign(
            &seed,
            "cameon-testnet",
            [1; 32],
            [3; 32],
            ONE_CAMEON_MICROS,
            usd.clone(),
            PaymentRail::Swift,
            2500,
            0,
            0,
            50,
            100,
            200,
        )
        .unwrap();
        let mut pool = TreasuryObservation {
            destination: usd,
            reported_liquid_minor: 2550,
            reported_reserved_minor: 0,
            observed_at: 102,
            independent_sources: 2,
        };
        let ok = prepare_cupp_coverage(
            &car,
            "cameon-testnet",
            &car.payer_public_mldsa87,
            &[1; 32],
            &[3; 32],
            103,
            3 * ONE_CAMEON_MICROS,
            &pool,
            &risk,
        )
        .unwrap();
        assert_eq!(ok.reservation_required_minor, 2550);
        pool.reported_liquid_minor = 2500;
        assert!(prepare_cupp_coverage(
            &car,
            "cameon-testnet",
            &car.payer_public_mldsa87,
            &[1; 32],
            &[3; 32],
            103,
            3 * ONE_CAMEON_MICROS,
            &pool,
            &risk
        )
        .is_err());
        pool.reported_liquid_minor = 2550;
        pool.independent_sources = 1;
        assert!(prepare_cupp_coverage(
            &car,
            "cameon-testnet",
            &car.payer_public_mldsa87,
            &[1; 32],
            &[3; 32],
            103,
            3 * ONE_CAMEON_MICROS,
            &pool,
            &risk
        )
        .is_err());
        pool.independent_sources = 2;
        pool.observed_at = 1;
        assert!(prepare_cupp_coverage(
            &car,
            "cameon-testnet",
            &car.payer_public_mldsa87,
            &[1; 32],
            &[3; 32],
            103,
            3 * ONE_CAMEON_MICROS,
            &pool,
            &risk
        )
        .is_err());
        pool.observed_at = 102;
        pool.reported_reserved_minor = 51;
        assert!(prepare_cupp_coverage(
            &car,
            "cameon-testnet",
            &car.payer_public_mldsa87,
            &[1; 32],
            &[3; 32],
            103,
            3 * ONE_CAMEON_MICROS,
            &pool,
            &risk
        )
        .is_err());
        let mut bad = risk;
        bad.hack_or_exploit = true;
        assert!(prepare_cupp_coverage(
            &car,
            "cameon-testnet",
            &car.payer_public_mldsa87,
            &[1; 32],
            &[3; 32],
            103,
            3 * ONE_CAMEON_MICROS,
            &pool,
            &bad
        )
        .is_err());
        bad = risk;
        bad.rank_ic_drift_bps = 3_500;
        bad.consecutive_drift_months = 2;
        assert!(prepare_cupp_coverage(
            &car,
            "cameon-testnet",
            &car.payer_public_mldsa87,
            &[1; 32],
            &[3; 32],
            103,
            3 * ONE_CAMEON_MICROS,
            &pool,
            &bad
        )
        .is_err());
        // A source in another currency cannot "fund" USD 25 on paper.
        pool.destination = Destination::fiat("EUR", 2).unwrap();
        assert!(prepare_cupp_coverage(
            &car,
            "cameon-testnet",
            &car.payer_public_mldsa87,
            &[1; 32],
            &[3; 32],
            103,
            3 * ONE_CAMEON_MICROS,
            &pool,
            &risk
        )
        .is_err());
    }

    #[test]
    fn cupp_bread_and_car_enforce_exact_funding_and_fail_closed_arq() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(harness)
            .unwrap()
            .join()
            .unwrap();
    }
}
