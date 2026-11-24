//! Universal Cameon purchase mandates, initiated ONLY by the buyer.
//!
//! The seller publishes an invoice in its own currency and need not hold or
//! accept Cameon. The buyer chooses to spend 1 Cameon (or another explicit
//! amount) and signs an EXACT seller payout instruction. A real external
//! financing source must provide the seller's currency before settlement.
//!
//! No token amount, signed mandate or funding snapshot *creates* fiat.
//! This module is a fail-closed OFFLINE checkout model, not a PSP or bank.

use crate::chameleon::{Destination, DestinationKind, PaymentRail};
use crate::PqCriptoError;
use mycelium_zkp::license::{mldsa_signing_key_from_seed, mldsa_verify, Keypair, Signer};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const DOMAIN: &str = "cameon/v1/payer-directed-exact-checkout";
const MAX_TTL_SECONDS: u64 = 900;
pub const ONE_CAMEON_MICROS: u64 = 1_000_000;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayerMandate {
    pub payment_id: [u8; 16],
    pub recipient_commitment: [u8; 32],
    pub invoice_commitment: [u8; 32],
    pub payer_public_mldsa87: Vec<u8>,
    /// Buyer selects Cameon for funding, independently of seller's invoice.
    pub cameon_spend_micros: u64,
    pub destination: Destination,
    pub rail: PaymentRail,
    /// Exactly what seller must receive, in the invoice currency minor units.
    pub exact_seller_receive_minor: u128,
    /// Tax included in seller's listed price: counted, NOT added a second time.
    pub tax_included_minor: u128,
    /// Other taxes legally due in addition to the seller's listed price.
    pub tax_extra_minor: u128,
    /// Fees borne by sponsor/payer and NOT deducted from seller's payout.
    pub provider_fee_minor: u128,
    pub created_at: u64,
    pub expires_at: u64,
    pub signature_mldsa87: Vec<u8>,
}

impl PayerMandate {
    fn check(&self, now: u64) -> Result<(), PqCriptoError> {
        self.destination.validate()?;
        if self.payment_id == [0; 16]
            || self.recipient_commitment == [0; 32]
            || self.invoice_commitment == [0; 32]
            || self.cameon_spend_micros == 0
            || self.exact_seller_receive_minor == 0
            || self.tax_included_minor > self.exact_seller_receive_minor
            || self.total_outlay_minor().is_none()
            || !self.rail.can_prepare(&self.destination)
            || self.expires_at <= self.created_at
            || self.expires_at - self.created_at > MAX_TTL_SECONDS
            || now < self.created_at
            || now >= self.expires_at
        {
            return Err(PqCriptoError::Price("invalid or expired payer mandate"));
        }
        Ok(())
    }

    pub fn total_outlay_minor(&self) -> Option<u128> {
        self.exact_seller_receive_minor
            .checked_add(self.tax_extra_minor)?
            .checked_add(self.provider_fee_minor)
    }

    fn digest(&self, chain: &str) -> Result<[u8; 32], PqCriptoError> {
        if chain.is_empty()
            || chain.len() > 63
            || !chain
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(PqCriptoError::Price("invalid Cameon chain id"));
        }
        let mut h = blake3::Hasher::new_derive_key(DOMAIN);
        h.update(&[chain.len() as u8]);
        h.update(chain.as_bytes());
        h.update(&self.payment_id);
        h.update(&self.recipient_commitment);
        h.update(&self.invoice_commitment);
        h.update(&(self.payer_public_mldsa87.len() as u64).to_be_bytes());
        h.update(&self.payer_public_mldsa87);
        h.update(&self.cameon_spend_micros.to_be_bytes());
        h.update(&[match self.destination.kind {
            DestinationKind::Cameon => 1,
            DestinationKind::Fiat => 2,
            DestinationKind::Crypto => 3,
        }]);
        for part in [&self.destination.symbol, &self.destination.network] {
            h.update(&[part.len() as u8]);
            h.update(part.as_bytes());
        }
        h.update(&[self.destination.decimals]);
        h.update(&[match self.rail {
            PaymentRail::Cameon => 1,
            PaymentRail::Pix => 2,
            PaymentRail::Swift => 3,
            PaymentRail::BricsDcms => 4,
            PaymentRail::CryptoNetwork => 5,
        }]);
        for amount in [
            self.exact_seller_receive_minor,
            self.tax_included_minor,
            self.tax_extra_minor,
            self.provider_fee_minor,
        ] {
            h.update(&amount.to_be_bytes());
        }
        h.update(&self.created_at.to_be_bytes());
        h.update(&self.expires_at.to_be_bytes());
        Ok(*h.finalize().as_bytes())
    }

    /// Generates authorization for an invoice identified out-of-band.
    /// This signature proves user INTENT, NOT token ownership or balance.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        seed: &[u8; 32],
        chain: &str,
        recipient_commitment: [u8; 32],
        invoice_commitment: [u8; 32],
        cameon_spend_micros: u64,
        destination: Destination,
        rail: PaymentRail,
        exact_seller_receive_minor: u128,
        tax_included_minor: u128,
        tax_extra_minor: u128,
        provider_fee_minor: u128,
        created_at: u64,
        expires_at: u64,
    ) -> Result<Self, PqCriptoError> {
        let seed = Zeroizing::new(*seed);
        let key = mldsa_signing_key_from_seed(&seed);
        let payer_public_mldsa87 = key.verifying_key().encode().as_slice().to_vec();
        let mut payment_id = [0; 16];
        rand::rngs::OsRng.fill_bytes(&mut payment_id);
        let mut item = Self {
            payment_id,
            recipient_commitment,
            invoice_commitment,
            payer_public_mldsa87,
            cameon_spend_micros,
            destination,
            rail,
            exact_seller_receive_minor,
            tax_included_minor,
            tax_extra_minor,
            provider_fee_minor,
            created_at,
            expires_at,
            signature_mldsa87: Vec::new(),
        };
        item.check(created_at)?;
        item.signature_mldsa87 = key
            .try_sign(&item.digest(chain)?)
            .map_err(|_| PqCriptoError::Cryptography)?
            .encode()
            .as_slice()
            .to_vec();
        Ok(item)
    }

    /// The expected payer key must come from authenticated wallet identity.
    pub fn verify(
        &self,
        chain: &str,
        expected_payer_key: &[u8],
        expected_recipient: &[u8; 32],
        expected_invoice: &[u8; 32],
        now: u64,
    ) -> Result<(), PqCriptoError> {
        self.check(now)?;
        if self.payer_public_mldsa87 != expected_payer_key
            || &self.recipient_commitment != expected_recipient
            || &self.invoice_commitment != expected_invoice
            || !mldsa_verify(
                expected_payer_key,
                &self.digest(chain)?,
                &self.signature_mldsa87,
            )
        {
            return Err(PqCriptoError::Authentication);
        }
        Ok(())
    }
}

/// A mathematical snapshot of *reported* liquid purchasing power.
/// Must NOT be treated as certified reserve, custody or a funding commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReportedFunding {
    /// Source could be service revenue, capital, grants or contracted credit,
    /// but must be denominated in the exact destination asset/minor units.
    pub liquid_minor: u128,
    pub precommitted_minor: u128,
}

impl ReportedFunding {
    pub fn free_minor(self) -> u128 {
        self.liquid_minor.saturating_sub(self.precommitted_minor)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedPayerCheckout {
    pub payment_id: [u8; 16],
    pub destination: Destination,
    pub rail: PaymentRail,
    pub cameon_debit_micros: u64,
    pub remaining_cameon_micros_if_spent: u64,
    pub seller_receive_minor: u128,
    pub tax_included_minor: u128,
    pub tax_extra_minor: u128,
    pub provider_fee_minor: u128,
    pub reported_funding_required_minor: u128,
    pub settled: bool,
}

/// Fail-closed preliminary plan. A real settlement MUST additionally check:
/// payer's unspent coins under consensus; PSP provider auth, live funding,
/// liquidity lock, tax requirements, and external confirmation. This type
/// deliberately has no "execute", "settle" or "credit" method.
#[allow(clippy::too_many_arguments)]
pub fn prepare_payer_checkout(
    mandate: &PayerMandate,
    chain: &str,
    expected_payer_key: &[u8],
    expected_recipient: &[u8; 32],
    expected_invoice: &[u8; 32],
    now: u64,
    reported_payer_cameon_balance_micros: u64,
    reported_funding: ReportedFunding,
) -> Result<PreparedPayerCheckout, PqCriptoError> {
    mandate.verify(
        chain,
        expected_payer_key,
        expected_recipient,
        expected_invoice,
        now,
    )?;
    let remainder = reported_payer_cameon_balance_micros
        .checked_sub(mandate.cameon_spend_micros)
        .ok_or(PqCriptoError::Price("insufficient reported Cameon balance"))?;
    let required = mandate
        .total_outlay_minor()
        .ok_or(PqCriptoError::Price("payout plus taxes and fees overflows"))?;
    if reported_funding.free_minor() < required {
        return Err(PqCriptoError::Price(
            "reported funding cannot cover the seller payout",
        ));
    }
    Ok(PreparedPayerCheckout {
        payment_id: mandate.payment_id,
        destination: mandate.destination.clone(),
        rail: mandate.rail,
        cameon_debit_micros: mandate.cameon_spend_micros,
        remaining_cameon_micros_if_spent: remainder,
        seller_receive_minor: mandate.exact_seller_receive_minor,
        tax_included_minor: mandate.tax_included_minor,
        tax_extra_minor: mandate.tax_extra_minor,
        provider_fee_minor: mandate.provider_fee_minor,
        reported_funding_required_minor: required,
        settled: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scenario() {
        let key = [29; 32];
        let dest = Destination::fiat("BRL", 2).unwrap();
        let mandate = PayerMandate::sign(
            &key,
            "cameon-testnet",
            [1; 32],
            [2; 32],
            ONE_CAMEON_MICROS,
            dest,
            PaymentRail::Pix,
            100,
            5,
            0,
            2,
            100,
            200,
        )
        .unwrap();
        let pk = mandate.payer_public_mldsa87.clone();
        let funding = ReportedFunding {
            liquid_minor: 102,
            precommitted_minor: 0,
        };
        let plan = prepare_payer_checkout(
            &mandate,
            "cameon-testnet",
            &pk,
            &[1; 32],
            &[2; 32],
            105,
            3 * ONE_CAMEON_MICROS,
            funding,
        )
        .unwrap();
        assert_eq!(plan.cameon_debit_micros, ONE_CAMEON_MICROS);
        assert_eq!(plan.remaining_cameon_micros_if_spent, 2 * ONE_CAMEON_MICROS);
        assert_eq!(plan.seller_receive_minor, 100);
        assert_eq!(plan.tax_included_minor, 5);
        assert_eq!(plan.reported_funding_required_minor, 102);
        assert!(!plan.settled);
        assert!(prepare_payer_checkout(
            &mandate,
            "cameon-testnet",
            &pk,
            &[1; 32],
            &[2; 32],
            105,
            ONE_CAMEON_MICROS - 1,
            funding
        )
        .is_err());
        assert!(prepare_payer_checkout(
            &mandate,
            "cameon-testnet",
            &pk,
            &[1; 32],
            &[2; 32],
            105,
            3 * ONE_CAMEON_MICROS,
            ReportedFunding {
                liquid_minor: 101,
                precommitted_minor: 0
            }
        )
        .is_err());
        assert!(prepare_payer_checkout(
            &mandate,
            "cameon-testnet",
            &pk,
            &[1; 32],
            &[2; 32],
            105,
            3 * ONE_CAMEON_MICROS,
            ReportedFunding {
                liquid_minor: 202,
                precommitted_minor: 101
            }
        )
        .is_err());
        assert!(prepare_payer_checkout(
            &mandate,
            "cameon-mainnet",
            &pk,
            &[1; 32],
            &[2; 32],
            105,
            3 * ONE_CAMEON_MICROS,
            funding
        )
        .is_err());
        assert!(prepare_payer_checkout(
            &mandate,
            "cameon-testnet",
            &pk,
            &[1; 32],
            &[9; 32],
            105,
            3 * ONE_CAMEON_MICROS,
            funding
        )
        .is_err());
        assert!(prepare_payer_checkout(
            &mandate,
            "cameon-testnet",
            &pk,
            &[1; 32],
            &[2; 32],
            201,
            3 * ONE_CAMEON_MICROS,
            funding
        )
        .is_err());
        let mut tampered = mandate.clone();
        tampered.exact_seller_receive_minor = 1;
        assert!(prepare_payer_checkout(
            &tampered,
            "cameon-testnet",
            &pk,
            &[1; 32],
            &[2; 32],
            105,
            3 * ONE_CAMEON_MICROS,
            funding
        )
        .is_err());
        let mut tampered = mandate.clone();
        tampered.tax_extra_minor = 100;
        assert!(prepare_payer_checkout(
            &tampered,
            "cameon-testnet",
            &pk,
            &[1; 32],
            &[2; 32],
            105,
            3 * ONE_CAMEON_MICROS,
            funding
        )
        .is_err());
    }

    #[test]
    fn one_cameon_for_one_brl_bread_with_three_cameon_wallet_offline_only() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(scenario)
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn no_arbitrary_payment_route_or_unbounded_taxes() {
        let pk = [1u8; 32];
        assert!(PayerMandate::sign(
            &pk,
            "cameon-testnet",
            [1; 32],
            [2; 32],
            1_000_000,
            Destination::fiat("USD", 2).unwrap(),
            PaymentRail::Pix,
            2500,
            0,
            0,
            0,
            100,
            200,
        )
        .is_err());
        assert!(PayerMandate::sign(
            &pk,
            "cameon-testnet",
            [1; 32],
            [2; 32],
            1_000_000,
            Destination::fiat("BRL", 2).unwrap(),
            PaymentRail::Pix,
            100,
            101,
            0,
            0,
            100,
            200,
        )
        .is_err());
        assert!(PayerMandate::sign(
            &pk,
            "cameon-testnet",
            [1; 32],
            [2; 32],
            1_000_000,
            Destination::fiat("BRL", 2).unwrap(),
            PaymentRail::Pix,
            100,
            0,
            u128::MAX,
            1,
            100,
            200,
        )
        .is_err());
    }
}
