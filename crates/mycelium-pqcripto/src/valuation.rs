//! Cameon fixed-price **commercial acceptance** and reserve math.
//!
//! A vendor can opt in to price goods at 1 CAMEON = 8 USDC.
//! Neither the posted policy nor a signed merchant order is a market price
//! or evidence of USDC collateral. Only a real externally verified
//! redemption/settlement provider can make USDC available for conversion.

use crate::PqCriptoError;
use mycelium_zkp::license::{mldsa_signing_key_from_seed, mldsa_verify, Signer};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Cameon and USDC both use six fractional digits inside this experimental
/// pricing API, which is deliberately distinct from the legacy MYC mint.
pub const CAMEON_MICROS: u64 = 1_000_000;
pub const TARGET_USDC_MICROS_PER_CAMEON: u64 = 8_000_000;
pub const TARGET_USDC_PER_CAMEON: u64 = 8;
pub const MAX_OFFER_TTL_SECONDS: u64 = 900;

const QUOTE_DOMAIN: &str = "cameon/v1/merchant-fixed-eight-quote";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CameonPrice {
    /// A policy amount: not a real-time sell price.
    pub cameon_micros: u64,
    pub usdc_target_micros: u64,
}

impl CameonPrice {
    /// Target only; no funds move. Math is checked and never saturates.
    pub fn for_cameon(cameon_micros: u64) -> Result<Self, PqCriptoError> {
        if cameon_micros == 0 {
            return Err(PqCriptoError::Price("Cameon amount must be positive"));
        }
        let usdc_target_micros = cameon_micros
            .checked_mul(TARGET_USDC_PER_CAMEON)
            .ok_or(PqCriptoError::Price("USDC amount overflows u64"))?;
        Ok(Self {
            cameon_micros,
            usdc_target_micros,
        })
    }

    /// Round UP to the nearest Cameon micro-unit, never undercharge merchant.
    pub fn for_usdc_target(usdc_target_micros: u64) -> Result<Self, PqCriptoError> {
        if usdc_target_micros == 0 {
            return Err(PqCriptoError::Price("USDC target must be positive"));
        }
        let cameon_micros = 1 + (usdc_target_micros - 1) / TARGET_USDC_PER_CAMEON;
        Self::for_cameon(cameon_micros)
    }
}

/// What a participating merchant ACTUALLY AGREED to accept for one order.
///
/// The merchant's identity verification key MUST be independently pinned.
/// Do not expose the merchant's order commitment in public logs or chains.
/// No one may treat this as a completed payment or guarantee of redemption.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MerchantAcceptance {
    pub quote_id: [u8; 16],
    pub order_commitment: [u8; 32],
    pub merchant_commitment: [u8; 32],
    pub cameon_micros: u64,
    pub usdc_pricing_micros: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature_mldsa87: Vec<u8>,
}

impl MerchantAcceptance {
    fn signing_digest(&self, chain: &str) -> Result<[u8; 32], PqCriptoError> {
        if chain.is_empty()
            || chain.len() > 63
            || !chain
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(PqCriptoError::Price("invalid chain id"));
        }
        let mut h = blake3::Hasher::new_derive_key(QUOTE_DOMAIN);
        h.update(&(chain.len() as u64).to_be_bytes());
        h.update(chain.as_bytes());
        h.update(&self.quote_id);
        h.update(&self.order_commitment);
        h.update(&self.merchant_commitment);
        h.update(&self.cameon_micros.to_be_bytes());
        h.update(&self.usdc_pricing_micros.to_be_bytes());
        h.update(&self.issued_at.to_be_bytes());
        h.update(&self.expires_at.to_be_bytes());
        Ok(*h.finalize().as_bytes())
    }

    fn check_terms(&self, now: u64) -> Result<(), PqCriptoError> {
        if self.quote_id == [0; 16]
            || self.order_commitment == [0; 32]
            || self.merchant_commitment == [0; 32]
            || self.expires_at <= self.issued_at
            || self.expires_at - self.issued_at > MAX_OFFER_TTL_SECONDS
            || now < self.issued_at
            || now >= self.expires_at
            || CameonPrice::for_cameon(self.cameon_micros)?.usdc_target_micros
                != self.usdc_pricing_micros
        {
            return Err(PqCriptoError::Price("invalid or expired commercial offer"));
        }
        Ok(())
    }

    /// The merchant agrees to the fixed unit price by signing the order.
    /// A trusted merchant directory is still necessary to pin their key.
    pub fn issue(
        signing_seed: &[u8; 32],
        chain: &str,
        order_commitment: [u8; 32],
        merchant_commitment: [u8; 32],
        cameon_micros: u64,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self, PqCriptoError> {
        let price = CameonPrice::for_cameon(cameon_micros)?;
        let mut id = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut id);
        let mut offer = Self {
            quote_id: id,
            order_commitment,
            merchant_commitment,
            cameon_micros,
            usdc_pricing_micros: price.usdc_target_micros,
            issued_at,
            expires_at,
            signature_mldsa87: Vec::new(),
        };
        offer.check_terms(issued_at)?;
        let seed = Zeroizing::new(*signing_seed);
        let sk = mldsa_signing_key_from_seed(&seed);
        let sig = sk
            .try_sign(&offer.signing_digest(chain)?)
            .map_err(|_| PqCriptoError::Cryptography)?;
        offer.signature_mldsa87 = sig.encode().as_slice().to_vec();
        Ok(offer)
    }

    pub fn verify(
        &self,
        trusted_merchant_public_mldsa87: &[u8],
        chain: &str,
        expected_order_commitment: &[u8; 32],
        expected_merchant_commitment: &[u8; 32],
        now: u64,
    ) -> Result<(), PqCriptoError> {
        self.check_terms(now)?;
        if &self.order_commitment != expected_order_commitment
            || &self.merchant_commitment != expected_merchant_commitment
            || !mldsa_verify(
                trusted_merchant_public_mldsa87,
                &self.signing_digest(chain)?,
                &self.signature_mldsa87,
            )
        {
            return Err(PqCriptoError::Authentication);
        }
        Ok(())
    }
}

/// Raw arithmetic on externally reported reserves, not cryptographic reserve
/// verification. Callers MUST NOT treat this calculation as a solvency audit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReportedReserveCoverage {
    pub circulating_cameon_micros: u64,
    pub reported_liquid_usdc_micros: u64,
    pub already_committed_usdc_micros: u64,
}

impl ReportedReserveCoverage {
    pub fn total_liability_usdc_micros(self) -> u128 {
        u128::from(self.circulating_cameon_micros) * u128::from(TARGET_USDC_PER_CAMEON)
    }

    pub fn available_reported_usdc_micros(self) -> u64 {
        self.reported_liquid_usdc_micros
            .saturating_sub(self.already_committed_usdc_micros)
    }

    pub fn reported_shortfall_usdc_micros(self) -> u128 {
        self.total_liability_usdc_micros()
            .saturating_sub(u128::from(self.available_reported_usdc_micros()))
    }

    /// Admission control only for OFFLINE policy calculations. Real issuance
    /// must additionally verify reserve ownership, source and finality.
    pub fn theoretical_additional_cameon_micros(self) -> u64 {
        let available = u128::from(self.available_reported_usdc_micros());
        let spare = available.saturating_sub(self.total_liability_usdc_micros());
        u64::try_from(spare / u128::from(TARGET_USDC_PER_CAMEON)).unwrap_or(u64::MAX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mycelium_zkp::license::Keypair;

    #[test]
    fn one_cameon_is_exactly_eight_usdc_as_policy() {
        assert_eq!(
            CameonPrice::for_cameon(CAMEON_MICROS)
                .unwrap()
                .usdc_target_micros,
            8_000_000
        );
        assert_eq!(
            CameonPrice::for_cameon(10 * CAMEON_MICROS)
                .unwrap()
                .usdc_target_micros,
            80_000_000
        );
        assert_eq!(
            CameonPrice::for_usdc_target(8_000_000)
                .unwrap()
                .cameon_micros,
            CAMEON_MICROS
        );
        assert_eq!(CameonPrice::for_usdc_target(9).unwrap().cameon_micros, 2);
        assert!(CameonPrice::for_cameon(u64::MAX).is_err());
    }

    #[test]
    fn reserve_math_requires_eight_usdc_for_one_cameon() {
        let mut r = ReportedReserveCoverage {
            circulating_cameon_micros: CAMEON_MICROS,
            reported_liquid_usdc_micros: 8_000_000,
            already_committed_usdc_micros: 0,
        };
        assert_eq!(r.total_liability_usdc_micros(), 8_000_000);
        assert_eq!(r.reported_shortfall_usdc_micros(), 0);
        assert_eq!(r.theoretical_additional_cameon_micros(), 0);
        r.already_committed_usdc_micros = 100_000;
        assert_eq!(r.reported_shortfall_usdc_micros(), 100_000);
        r.reported_liquid_usdc_micros = 24_100_000;
        assert_eq!(r.theoretical_additional_cameon_micros(), 2_000_000);
    }

    #[test]
    fn signed_merchant_offer_enforces_price_identity_and_time() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let seed = [13u8; 32];
                let pubkey = mldsa_signing_key_from_seed(&seed)
                    .verifying_key()
                    .encode()
                    .as_slice()
                    .to_vec();
                let q = MerchantAcceptance::issue(
                    &seed,
                    "cameon-mainnet",
                    [1; 32],
                    [2; 32],
                    CAMEON_MICROS,
                    1_800_000_000,
                    1_800_000_600,
                )
                .unwrap();
                assert_eq!(q.usdc_pricing_micros, 8_000_000);
                q.verify(&pubkey, "cameon-mainnet", &[1; 32], &[2; 32], 1_800_000_001)
                    .unwrap();
                assert!(q
                    .verify(&pubkey, "other-chain", &[1; 32], &[2; 32], 1_800_000_001)
                    .is_err());
                assert!(q
                    .verify(&pubkey, "cameon-mainnet", &[3; 32], &[2; 32], 1_800_000_001)
                    .is_err());
                assert!(q
                    .verify(&pubkey, "cameon-mainnet", &[1; 32], &[3; 32], 1_800_000_001)
                    .is_err());
                assert!(q
                    .verify(&pubkey, "cameon-mainnet", &[1; 32], &[2; 32], 1_800_000_601)
                    .is_err());
                let mut fake = q.clone();
                fake.usdc_pricing_micros = 1;
                assert!(fake
                    .verify(&pubkey, "cameon-mainnet", &[1; 32], &[2; 32], 1_800_000_001)
                    .is_err());
                let mut fake = q.clone();
                fake.signature_mldsa87[0] ^= 1;
                assert!(fake
                    .verify(&pubkey, "cameon-mainnet", &[1; 32], &[2; 32], 1_800_000_001)
                    .is_err());
            })
            .unwrap()
            .join()
            .unwrap();
    }
}
