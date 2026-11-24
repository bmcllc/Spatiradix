//! Cameon contextual valuation: one native asset, multiple accepted values.
//!
//! Different counterparties may sign different prices for the *same* amount
//! of Cameon. This does not create fiat or cryptocurrency liquidity.
//! A signed quote is an offer, NOT settlement, collateral, or market value.

use crate::PqCriptoError;
use mycelium_zkp::license::{mldsa_signing_key_from_seed, mldsa_verify, Signer};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const DOMAIN: &str = "cameon/v1/contextual-valuation-quote";
const MAX_TTL_SECS: u64 = 900;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DestinationKind {
    Cameon,
    Fiat,
    Crypto,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Destination {
    pub kind: DestinationKind,
    /// A destination code, not a promise that an external institution supports it.
    pub symbol: String,
    /// Explicit network for crypto, or empty for fiat.
    pub network: String,
    pub decimals: u8,
}

impl Destination {
    pub fn native() -> Self {
        Self {
            kind: DestinationKind::Cameon,
            symbol: "CAMEON".into(),
            network: "mycelium".into(),
            decimals: 6,
        }
    }

    pub fn fiat(symbol: &str, decimals: u8) -> Result<Self, PqCriptoError> {
        let target = Self {
            kind: DestinationKind::Fiat,
            symbol: symbol.into(),
            network: String::new(),
            decimals,
        };
        target.validate()?;
        Ok(target)
    }

    pub fn crypto(symbol: &str, network: &str, decimals: u8) -> Result<Self, PqCriptoError> {
        let target = Self {
            kind: DestinationKind::Crypto,
            symbol: symbol.into(),
            network: network.into(),
            decimals,
        };
        target.validate()?;
        Ok(target)
    }

    pub(crate) fn validate(&self) -> Result<(), PqCriptoError> {
        let valid = match self.kind {
            DestinationKind::Cameon => *self == Self::native(),
            DestinationKind::Fiat => {
                self.symbol.len() == 3
                    && self.symbol.bytes().all(|b| b.is_ascii_uppercase())
                    && self.network.is_empty()
                    && self.decimals <= 6
            }
            DestinationKind::Crypto => {
                (2..=16).contains(&self.symbol.len())
                    && self
                        .symbol
                        .bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
                    && (1..=63).contains(&self.network.len())
                    && self
                        .network
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                    && self.decimals <= 18
            }
        };
        if valid {
            Ok(())
        } else {
            Err(PqCriptoError::Price("invalid destination"))
        }
    }
}

/// The rail only describes a candidate adapter; it does not send a payment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PaymentRail {
    Cameon,
    Pix,
    Swift,
    BricsDcms,
    CryptoNetwork,
}

impl PaymentRail {
    pub(crate) fn can_prepare(self, target: &Destination) -> bool {
        match self {
            Self::Cameon => target.kind == DestinationKind::Cameon,
            Self::Pix => target.kind == DestinationKind::Fiat && target.symbol == "BRL",
            Self::Swift => target.kind == DestinationKind::Fiat,
            Self::BricsDcms => target.kind != DestinationKind::Cameon,
            Self::CryptoNetwork => target.kind == DestinationKind::Crypto,
        }
    }
}

/// A unique, time-limited, provider-signed agreement on the amount of the
/// destination currency for a specific Cameon amount and recipient.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextualQuote {
    pub quote_id: [u8; 16],
    pub provider_commitment: [u8; 32],
    pub recipient_commitment: [u8; 32],
    pub invoice_commitment: [u8; 32],
    pub cameon_micros: u64,
    pub destination: Destination,
    pub rail: PaymentRail,
    /// Exact amount to be received by the beneficiary, in destination minor units.
    pub receive_minor: u128,
    /// Fee in destination minor units. Not necessarily deducted from receive_minor.
    pub fee_minor: u128,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature_mldsa87: Vec<u8>,
}

impl ContextualQuote {
    fn check_terms(&self, now: u64) -> Result<(), PqCriptoError> {
        self.destination.validate()?;
        if self.quote_id == [0; 16]
            || self.provider_commitment == [0; 32]
            || self.recipient_commitment == [0; 32]
            || self.invoice_commitment == [0; 32]
            || self.cameon_micros == 0
            || self.receive_minor == 0
            || self.receive_minor.checked_add(self.fee_minor).is_none()
            || !self.rail.can_prepare(&self.destination)
            || self.expires_at <= self.issued_at
            || self.expires_at - self.issued_at > MAX_TTL_SECS
            || now < self.issued_at
            || now >= self.expires_at
        {
            return Err(PqCriptoError::Price("invalid or expired contextual quote"));
        }
        Ok(())
    }

    fn message(&self, chain: &str) -> Result<[u8; 32], PqCriptoError> {
        if chain.is_empty()
            || chain.len() > 63
            || !chain
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(PqCriptoError::Price("invalid chain id"));
        }
        let mut h = blake3::Hasher::new_derive_key(DOMAIN);
        h.update(&[chain.len() as u8]);
        h.update(chain.as_bytes());
        h.update(&self.quote_id);
        h.update(&self.provider_commitment);
        h.update(&self.recipient_commitment);
        h.update(&self.invoice_commitment);
        h.update(&self.cameon_micros.to_be_bytes());
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
        h.update(&self.receive_minor.to_be_bytes());
        h.update(&self.fee_minor.to_be_bytes());
        h.update(&self.issued_at.to_be_bytes());
        h.update(&self.expires_at.to_be_bytes());
        Ok(*h.finalize().as_bytes())
    }

    /// Requires a genuine counterparty private key, not a generic wallet key.
    /// A malicious/self-issued quote must never count as proof of liquidity.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        chain: &str,
        provider_seed: &[u8; 32],
        provider_commitment: [u8; 32],
        recipient_commitment: [u8; 32],
        invoice_commitment: [u8; 32],
        cameon_micros: u64,
        destination: Destination,
        rail: PaymentRail,
        receive_minor: u128,
        fee_minor: u128,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self, PqCriptoError> {
        let mut quote_id = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut quote_id);
        let mut quote = Self {
            quote_id,
            provider_commitment,
            recipient_commitment,
            invoice_commitment,
            cameon_micros,
            destination,
            rail,
            receive_minor,
            fee_minor,
            issued_at,
            expires_at,
            signature_mldsa87: Vec::new(),
        };
        quote.check_terms(issued_at)?;
        let seed = Zeroizing::new(*provider_seed);
        let key = mldsa_signing_key_from_seed(&seed);
        quote.signature_mldsa87 = key
            .try_sign(&quote.message(chain)?)
            .map_err(|_| PqCriptoError::Cryptography)?
            .encode()
            .as_slice()
            .to_vec();
        Ok(quote)
    }

    /// The key MUST be pinned in a trusted counterparty directory.
    pub fn verify(
        &self,
        chain: &str,
        provider_public: &[u8],
        expected_provider: &[u8; 32],
        expected_recipient: &[u8; 32],
        expected_invoice: &[u8; 32],
        now: u64,
    ) -> Result<(), PqCriptoError> {
        self.check_terms(now)?;
        if &self.provider_commitment != expected_provider
            || &self.recipient_commitment != expected_recipient
            || &self.invoice_commitment != expected_invoice
            || !mldsa_verify(
                provider_public,
                &self.message(chain)?,
                &self.signature_mldsa87,
            )
        {
            return Err(PqCriptoError::Authentication);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedInstruction {
    pub cameon_micros: u64,
    pub destination: Destination,
    pub rail: PaymentRail,
    pub expected_receive_minor: u128,
    /// No funds have moved, even if the quote verifies.
    pub settled: bool,
}

impl PreparedInstruction {
    pub fn from_quote(
        quote: &ContextualQuote,
        chain: &str,
        provider_public: &[u8],
        expected_provider: &[u8; 32],
        expected_recipient: &[u8; 32],
        expected_invoice: &[u8; 32],
        now: u64,
    ) -> Result<Self, PqCriptoError> {
        quote.verify(
            chain,
            provider_public,
            expected_provider,
            expected_recipient,
            expected_invoice,
            now,
        )?;
        Ok(Self {
            cameon_micros: quote.cameon_micros,
            destination: quote.destination.clone(),
            rail: quote.rail,
            expected_receive_minor: quote.receive_minor,
            settled: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mycelium_zkp::license::Keypair;

    fn exercise() {
        let seed = [7u8; 32];
        let provider_public = mldsa_signing_key_from_seed(&seed)
            .verifying_key()
            .encode()
            .as_slice()
            .to_vec();
        let target_brl = Destination::fiat("BRL", 2).unwrap();
        let target_btc = Destination::crypto("BTC", "bitcoin-mainnet", 8).unwrap();
        let q_brl = ContextualQuote::issue(
            "cameon",
            &seed,
            [1; 32],
            [2; 32],
            [3; 32],
            1_000_000,
            target_brl,
            PaymentRail::Pix,
            4_250,
            10,
            200,
            400,
        )
        .unwrap();
        let q_btc = ContextualQuote::issue(
            "cameon",
            &seed,
            [1; 32],
            [2; 32],
            [3; 32],
            1_000_000,
            target_btc,
            PaymentRail::CryptoNetwork,
            30_000,
            10,
            200,
            400,
        )
        .unwrap();
        let a = PreparedInstruction::from_quote(
            &q_brl,
            "cameon",
            &provider_public,
            &[1; 32],
            &[2; 32],
            &[3; 32],
            220,
        )
        .unwrap();
        let b = PreparedInstruction::from_quote(
            &q_btc,
            "cameon",
            &provider_public,
            &[1; 32],
            &[2; 32],
            &[3; 32],
            220,
        )
        .unwrap();
        assert_eq!(a.cameon_micros, b.cameon_micros);
        assert_eq!(a.expected_receive_minor, 4250);
        assert_eq!(b.expected_receive_minor, 30000);
        assert!(!a.settled && !b.settled);
        let mut wrong = q_brl.clone();
        wrong.receive_minor = 90000;
        assert!(wrong
            .verify(
                "cameon",
                &provider_public,
                &[1; 32],
                &[2; 32],
                &[3; 32],
                220
            )
            .is_err());
        assert!(q_brl
            .verify("other", &provider_public, &[1; 32], &[2; 32], &[3; 32], 220)
            .is_err());
        assert!(q_brl
            .verify(
                "cameon",
                &provider_public,
                &[1; 32],
                &[2; 32],
                &[3; 32],
                401
            )
            .is_err());
        assert!(q_brl
            .verify(
                "cameon",
                &provider_public,
                &[1; 32],
                &[4; 32],
                &[3; 32],
                220
            )
            .is_err());
        assert!(ContextualQuote::issue(
            "cameon",
            &seed,
            [1; 32],
            [2; 32],
            [3; 32],
            1_000_000,
            Destination::crypto("BTC", "bitcoin-mainnet", 8).unwrap(),
            PaymentRail::Pix,
            30000,
            0,
            200,
            400
        )
        .is_err());
    }

    #[test]
    fn cameon_has_any_explicitly_agreed_contextual_value_but_not_infinite_value() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(exercise)
            .unwrap()
            .join()
            .unwrap();
    }
}
