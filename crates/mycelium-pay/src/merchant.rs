//! Voluntary merchant quote for MYC purchases at the project's indicative
//! 1 MYC = 8 USDC unit rate. An offer is NOT liquid USDC, redemption, debit,
//! credit, merchant identity vetting, bank settlement or cashu redemption.
//!
//! The merchant chooses the price and explicitly signs the implied MYC price.
//! The buyer verifies against a pinned merchant x-only public key. Quotes are
//! intended to be conveyed through an authenticated, encrypted private channel.

use crate::cbor::{self, Value};
use crate::PayError;
use rand::RngCore;
use secp256k1::{schnorr, Keypair, SecretKey, XOnlyPublicKey, SECP256K1};

pub const MYC_USDC_INDICATIVE_RATE: u64 = 8;
const MAX_QUOTE_TTL_SECS: u64 = 15 * 60;
const DOMAIN: &str = "mycelium/v1/pay/merchant-quote";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerchantQuote {
    pub quote_id: [u8; 16],
    /// Salted invoice identifier, not the original name, cart or customer.
    pub invoice_commitment: [u8; 32],
    pub merchant_account: String,
    /// Pinned BIP340 merchant identity (not necessarily the bank account owner).
    pub merchant_xonly: [u8; 32],
    pub usdc_reference_micros: u64,
    pub myc_to_pay_micros: u64,
    pub rate_usdc_per_myc: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: [u8; 64],
}

impl MerchantQuote {
    /// Integer conversion, ceil to the nearest micro MYC to avoid undercharging
    /// when USDC 6-decimal units are not divisible by the per-MYC rate.
    pub fn quote_myc_amount(usdc_micros: u64) -> Result<u64, PayError> {
        if usdc_micros == 0 {
            return Err(PayError::Envelope("preço USDC precisa ser positivo"));
        }
        Ok(1 + (usdc_micros - 1) / MYC_USDC_INDICATIVE_RATE)
    }

    pub fn issue(
        signing_seed: &[u8; 32],
        merchant_account: String,
        invoice_commitment: [u8; 32],
        usdc_reference_micros: u64,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self, PayError> {
        let sk = SecretKey::from_byte_array(*signing_seed)
            .map_err(|_| PayError::Envelope("chave de comerciante inválida"))?;
        let keypair = Keypair::from_secret_key(SECP256K1, &sk);
        let mut quote_id = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut quote_id);
        let mut q = Self {
            quote_id,
            invoice_commitment,
            merchant_account,
            merchant_xonly: keypair.x_only_public_key().0.serialize(),
            usdc_reference_micros,
            myc_to_pay_micros: Self::quote_myc_amount(usdc_reference_micros)?,
            rate_usdc_per_myc: MYC_USDC_INDICATIVE_RATE,
            issued_at,
            expires_at,
            signature: [0; 64],
        };
        q.validate_terms(issued_at)?;
        let sig = SECP256K1.sign_schnorr_no_aux_rand(&q.signing_hash()?, &keypair);
        q.signature.copy_from_slice(sig.as_ref());
        Ok(q)
    }

    fn validate_terms(&self, now: u64) -> Result<(), PayError> {
        let a = self.merchant_account.as_bytes();
        if a.is_empty()
            || a.len() > 96
            || a[0] == b'-'
            || a[a.len() - 1] == b'-'
            || !a
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
        {
            return Err(PayError::Envelope("conta do comerciante inválida"));
        }
        if self.invoice_commitment == [0; 32] || self.quote_id == [0; 16] {
            return Err(PayError::Envelope("identificador ou compromisso inválido"));
        }
        if self.rate_usdc_per_myc != MYC_USDC_INDICATIVE_RATE
            || self.myc_to_pay_micros != Self::quote_myc_amount(self.usdc_reference_micros)?
        {
            return Err(PayError::Envelope(
                "valor MYC não corresponde à cotação assinada",
            ));
        }
        if self.expires_at <= self.issued_at
            || self.expires_at - self.issued_at > MAX_QUOTE_TTL_SECS
            || now < self.issued_at
            || now >= self.expires_at
        {
            return Err(PayError::Envelope(
                "oferta expirada ou janela temporal inválida",
            ));
        }
        Ok(())
    }

    /// Verify exact merchant key PIN and the signed quote terms.
    /// The caller must independently authenticate the merchant's pin.
    pub fn verify(&self, expected_merchant_xonly: &[u8; 32], now: u64) -> Result<(), PayError> {
        self.validate_terms(now)?;
        if &self.merchant_xonly != expected_merchant_xonly {
            return Err(PayError::BadSignature);
        }
        let pk = XOnlyPublicKey::from_byte_array(self.merchant_xonly)
            .map_err(|_| PayError::BadSignature)?;
        let sig = schnorr::Signature::from_byte_array(self.signature);
        SECP256K1
            .verify_schnorr(&sig, &self.signing_hash()?, &pk)
            .map_err(|_| PayError::BadSignature)
    }

    /// Deterministic binary canonical representation of all terms except sig.
    fn terms(&self) -> Value {
        Value::Map(vec![
            (0, Value::Bytes(self.quote_id.to_vec())),
            (1, Value::Bytes(self.invoice_commitment.to_vec())),
            (2, Value::Text(self.merchant_account.clone())),
            (3, Value::Bytes(self.merchant_xonly.to_vec())),
            (4, Value::Uint(self.usdc_reference_micros)),
            (5, Value::Uint(self.myc_to_pay_micros)),
            (6, Value::Uint(self.rate_usdc_per_myc)),
            (7, Value::Uint(self.issued_at)),
            (8, Value::Uint(self.expires_at)),
        ])
    }

    pub fn signing_hash(&self) -> Result<[u8; 32], PayError> {
        let canonical = cbor::encode(&self.terms())?;
        Ok(blake3::derive_key(DOMAIN, &canonical))
    }

    pub fn to_wire(&self) -> Result<Vec<u8>, PayError> {
        let mut fields = match self.terms() {
            Value::Map(fields) => fields,
            _ => unreachable!(),
        };
        fields.push((9, Value::Bytes(self.signature.to_vec())));
        cbor::encode(&Value::Map(fields))
    }

    pub fn from_wire(
        wire: &[u8],
        expected_merchant_xonly: &[u8; 32],
        now: u64,
    ) -> Result<Self, PayError> {
        let Value::Map(fields) = cbor::decode(wire)? else {
            return Err(PayError::Envelope("oferta não é mapa canônico"));
        };
        if fields.len() != 10 || fields.iter().enumerate().any(|(i, (k, _))| *k != i as u64) {
            return Err(PayError::Envelope("campos desconhecidos na oferta"));
        }
        let mut it = fields.into_iter().map(|(_, v)| v);
        fn fixed<const N: usize>(v: Value) -> Result<[u8; N], PayError> {
            match v {
                Value::Bytes(v) => v
                    .try_into()
                    .map_err(|_| PayError::Envelope("comprimento de bytes inválido")),
                _ => Err(PayError::Envelope("campo deveria conter bytes")),
            }
        }
        fn number(v: Value) -> Result<u64, PayError> {
            match v {
                Value::Uint(v) => Ok(v),
                _ => Err(PayError::Envelope("campo deveria conter inteiro")),
            }
        }
        let quote = Self {
            quote_id: fixed(it.next().unwrap())?,
            invoice_commitment: fixed(it.next().unwrap())?,
            merchant_account: match it.next().unwrap() {
                Value::Text(v) => v,
                _ => return Err(PayError::Envelope("conta precisa ser texto")),
            },
            merchant_xonly: fixed(it.next().unwrap())?,
            usdc_reference_micros: number(it.next().unwrap())?,
            myc_to_pay_micros: number(it.next().unwrap())?,
            rate_usdc_per_myc: number(it.next().unwrap())?,
            issued_at: number(it.next().unwrap())?,
            expires_at: number(it.next().unwrap())?,
            signature: fixed(it.next().unwrap())?,
        };
        quote.verify(expected_merchant_xonly, now)?;
        Ok(quote)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn issue(price: u64) -> MerchantQuote {
        MerchantQuote::issue(
            &[7u8; 32],
            "mbk-merchant".into(),
            [8; 32],
            price,
            1_800_000_000,
            1_800_000_600,
        )
        .unwrap()
    }
    #[test]
    fn merchant_voluntarily_accepts_exact_eight_to_one_rate() {
        let quote = issue(80_000_000);
        assert_eq!(quote.myc_to_pay_micros, 10_000_000);
        assert_eq!(quote.rate_usdc_per_myc, 8);
        quote.verify(&quote.merchant_xonly, 1_800_000_100).unwrap();
        let wire = quote.to_wire().unwrap();
        assert_eq!(
            MerchantQuote::from_wire(&wire, &quote.merchant_xonly, 1_800_000_100).unwrap(),
            quote
        );
    }
    #[test]
    fn rounds_up_uneven_prices_and_never_saturates() {
        assert_eq!(MerchantQuote::quote_myc_amount(1).unwrap(), 1);
        assert_eq!(MerchantQuote::quote_myc_amount(8).unwrap(), 1);
        assert_eq!(MerchantQuote::quote_myc_amount(9).unwrap(), 2);
        assert_eq!(
            MerchantQuote::quote_myc_amount(u64::MAX).unwrap(),
            2_305_843_009_213_693_952
        );
        assert!(MerchantQuote::quote_myc_amount(0).is_err());
    }
    #[test]
    fn rejects_tampered_price_account_signature_and_expiration() {
        let q = issue(80_000_000);
        let mut tampered = q.clone();
        tampered.myc_to_pay_micros = 1;
        assert!(tampered.verify(&q.merchant_xonly, 1_800_000_100).is_err());
        tampered = q.clone();
        tampered.merchant_account = "mbk-attacker".into();
        assert!(tampered.verify(&q.merchant_xonly, 1_800_000_100).is_err());
        tampered = q.clone();
        tampered.signature[7] ^= 1;
        assert!(tampered.verify(&q.merchant_xonly, 1_800_000_100).is_err());
        assert!(q.verify(&[0xff; 32], 1_800_000_100).is_err());
        assert!(q.verify(&q.merchant_xonly, 1_800_000_601).is_err());
        assert!(q.verify(&q.merchant_xonly, 1_799_999_999).is_err());
        assert!(MerchantQuote::issue(&[7; 32], "mbk-merchant".into(), [8; 32], 8, 10, 10).is_err());
    }
    #[test]
    fn rejects_modified_wire_fields_and_extra_cbor_keys() {
        let q = issue(8_000_000);
        let mut wire = q.to_wire().unwrap();
        *wire.last_mut().unwrap() ^= 1;
        assert!(MerchantQuote::from_wire(&wire, &q.merchant_xonly, 1_800_000_001).is_err());
        let mut map = match cbor::decode(&q.to_wire().unwrap()).unwrap() {
            Value::Map(v) => v,
            _ => unreachable!(),
        };
        map.push((10, Value::Uint(9)));
        assert!(MerchantQuote::from_wire(
            &cbor::encode(&Value::Map(map)).unwrap(),
            &q.merchant_xonly,
            1_800_000_001
        )
        .is_err());
    }
}
