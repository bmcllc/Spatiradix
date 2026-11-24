//! Merchant-accepted 1:8 MYC purchase intent, without pretending settlement.
//!
//! A merchant signs the quoted price; the buyer pins both the merchant key
//! and the bank account name using a separate trusted merchant registry.
//! This creates a prepared MYC-rail intent only; no debit, credit, reserve,
//! automatic investment or external Pix/SWIFT/BRICS transfer occurs.

use crate::core::{GatewayType, PaymentIntent, TransactionState};
use crate::error::GatewayError;
use mycelium_pay::merchant::MerchantQuote;
use serde_json::json;

#[derive(Clone, Debug)]
pub struct PreparedMycCheckout {
    pub intent: PaymentIntent,
    pub merchant_quote_id: String,
    pub reference_usdc_micros: u64,
    /// This is a merchant-agreed *price*, not a redeemable exchange rate.
    pub rate_usdc_per_myc: u64,
    pub bank_posting_completed: bool,
}

/// Preconditions:
/// - The merchant public key/account pair MUST have been pinned through an
///   authenticated out-of-band merchant registry.
/// - The quote signature/expiry/amount MUST verify.
/// - The bank must eventually debit and credit before marking the result
///   settled, but this function does not itself move any funds.
pub fn prepare_myc_purchase(
    quote: &MerchantQuote,
    expected_merchant_xonly: &[u8; 32],
    expected_merchant_account: &str,
    payer_did: &str,
    now: u64,
) -> Result<PreparedMycCheckout, GatewayError> {
    quote
        .verify(expected_merchant_xonly, now)
        .map_err(|err| GatewayError::Crypto(format!("merchant quote refused: {err}")))?;
    if quote.merchant_account != expected_merchant_account {
        return Err(GatewayError::InvalidTarget(
            "merchant bank account differs from pinned merchant identity".into(),
        ));
    }
    if !payer_did.starts_with("did:mycelium:") || payer_did.len() > 180 {
        return Err(GatewayError::InvalidTarget(
            "payer DID must be a Mycelium identity".into(),
        ));
    }
    let quote_id = hex::encode(quote.quote_id);
    let intent = PaymentIntent::auto_route(
        quote.myc_to_pay_micros,
        "MYC",
        payer_did,
        format!("myc:{}", quote.merchant_account),
        json!({
            "idempotency_key": format!("merchant-v1:{quote_id}"),
            "merchant_quote_id": quote_id,
            "merchant_quote_hash": hex::encode(quote.signing_hash().map_err(|err| GatewayError::Crypto(err.to_string()))?),
            "invoice_commitment": hex::encode(quote.invoice_commitment),
            "quoted_usdc_reference_micros": quote.usdc_reference_micros,
            "merchant_accepted_rate_usdc_per_myc": quote.rate_usdc_per_myc,
            "quote_expires_at": quote.expires_at,
            "kind": "internal_merchant_checkout",
            "financial_state": "prepared_not_debited",
        }),
    )?;
    if intent.gateway != GatewayType::MycRail || intent.state != TransactionState::Initiated {
        return Err(GatewayError::Crypto(
            "unexpected merchant intent state".into(),
        ));
    }
    Ok(PreparedMycCheckout {
        intent,
        merchant_quote_id: quote_id,
        reference_usdc_micros: quote.usdc_reference_micros,
        rate_usdc_per_myc: quote.rate_usdc_per_myc,
        bank_posting_completed: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn quote() -> MerchantQuote {
        MerchantQuote::issue(
            &[0x34; 32],
            "mbk-merchant".into(),
            [0x58; 32],
            80_000_000,
            1_800_000_000,
            1_800_000_600,
        )
        .unwrap()
    }

    #[test]
    fn merchant_accepts_80_usdc_price_as_10_myc_without_settlement() {
        let merchant = quote();
        let signed = prepare_myc_purchase(
            &merchant,
            &merchant.merchant_xonly,
            "mbk-merchant",
            "did:mycelium:buyer",
            1_800_000_020,
        )
        .unwrap();
        assert_eq!(signed.intent.amount_micros, 10_000_000);
        assert_eq!(signed.reference_usdc_micros, 80_000_000);
        assert_eq!(signed.rate_usdc_per_myc, 8);
        assert_eq!(signed.intent.receiver_id, "myc:mbk-merchant");
        assert_eq!(signed.intent.currency, "MYC");
        assert_eq!(signed.intent.state, TransactionState::Initiated);
        assert!(!signed.bank_posting_completed);
        let repeated = prepare_myc_purchase(
            &merchant,
            &merchant.merchant_xonly,
            "mbk-merchant",
            "did:mycelium:buyer",
            1_800_000_021,
        )
        .unwrap();
        assert_eq!(repeated.intent.id, signed.intent.id);
    }

    #[test]
    fn wrong_merchant_account_or_key_cannot_redirect_merchant_purchase() {
        let q = quote();
        assert!(prepare_myc_purchase(
            &q,
            &q.merchant_xonly,
            "mbk-attacker",
            "did:mycelium:buyer",
            1_800_000_001
        )
        .is_err());
        assert!(prepare_myc_purchase(
            &q,
            &[0x17; 32],
            "mbk-merchant",
            "did:mycelium:buyer",
            1_800_000_001
        )
        .is_err());
        assert!(
            prepare_myc_purchase(&q, &q.merchant_xonly, "mbk-merchant", "anon", 1_800_000_001)
                .is_err()
        );
        assert!(prepare_myc_purchase(
            &q,
            &q.merchant_xonly,
            "mbk-merchant",
            "did:mycelium:buyer",
            1_800_001_000
        )
        .is_err());
    }
}
