//! W8: fixed, historical laboratory quote + preparation smoke test.
//! No dispatch, posting, minting, bank/PSP access, or export of actionable intents.
use crate::{prepare_myc_purchase, run_pix_privacy_lab, GatewayType, TransactionState};
use mycelium_pay::merchant::MerchantQuote;
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroizing;

type R<T> = Result<T, &'static str>;
const CLOCK: u64 = 1_700_000_000; // deliberately historical, never valid in production today
const EXPIRY: u64 = CLOCK + 60;
const ACCOUNT: &str = "w8-lab-fixture";
const PAYER: &str = "did:mycelium:w8-lab-fixture";
const PRICE: u64 = 80_000_000; // independent illustrative USDC reference, NOT BRL or W6 credits
fn quote() -> R<MerchantQuote> {
    let mut seed = Zeroizing::new([0u8; 32]);
    OsRng
        .try_fill_bytes(&mut *seed)
        .map_err(|_| "randomness unavailable")?;
    let mut salt = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut salt)
        .map_err(|_| "randomness unavailable")?;
    let commitment = blake3::derive_key("bse/w8/lab/fictional-invoice", &salt);
    MerchantQuote::issue(&seed, ACCOUNT.into(), commitment, PRICE, CLOCK, EXPIRY)
        .map_err(|_| "fixture quote failed")
}
#[derive(Debug, PartialEq, Eq)]
pub struct PayLabReport {
    pub w7_qa_ok: bool,
    pub quote_roundtrip: bool,
    pub signature_ok: bool,
    pub wrong_pin_rejected: bool,
    pub wrong_account_rejected: bool,
    pub expired_rejected: bool,
    pub tampered_quote_rejected: bool,
    pub unsigned_quote_rejected: bool,
    pub prepared_only: bool,
    pub stable_retry_id: bool,
    pub bank_posting_completed: bool,
}
impl PayLabReport {
    pub const fn is_verified(&self) -> bool {
        false
    }
}
/// No caller inputs. The result contains only aggregate QA outcomes.
pub fn run_pay_lab() -> R<PayLabReport> {
    let w7 = run_pix_privacy_lab()?;
    let w7_qa_ok = w7.encrypted_roundtrip && w7.combinations_checked == 10;
    let q = quote()?;
    // Pin from the locally generated fixture, not real merchant authentication.
    let pin = q.merchant_xonly;
    let wire = q.to_wire().map_err(|_| "quote encoding failed")?;
    let parsed =
        MerchantQuote::from_wire(&wire, &pin, CLOCK + 1).map_err(|_| "quote decoding failed")?;
    let quote_roundtrip = parsed == q;
    let signature_ok = parsed.verify(&pin, CLOCK + 1).is_ok();
    let mut wrong_pin = pin;
    wrong_pin[0] ^= 1;
    let wrong_pin_rejected = MerchantQuote::from_wire(&wire, &wrong_pin, CLOCK + 1).is_err();
    let wrong_account_rejected =
        prepare_myc_purchase(&parsed, &pin, "w8-other-fixture", PAYER, CLOCK + 1).is_err();
    let expired_rejected = MerchantQuote::from_wire(&wire, &pin, EXPIRY).is_err()
        && prepare_myc_purchase(&parsed, &pin, ACCOUNT, PAYER, EXPIRY).is_err();
    let mut altered = parsed.clone();
    altered.invoice_commitment[0] ^= 1;
    let tampered_quote_rejected = altered.verify(&pin, CLOCK + 1).is_err();
    let mut unsigned = parsed.clone();
    unsigned.signature = [0; 64];
    let unsigned_quote_rejected = unsigned.verify(&pin, CLOCK + 1).is_err();
    let prepared = prepare_myc_purchase(&parsed, &pin, ACCOUNT, PAYER, CLOCK + 1)
        .map_err(|_| "fixture preparation failed")?;
    let retry = prepare_myc_purchase(&parsed, &pin, ACCOUNT, PAYER, CLOCK + 2)
        .map_err(|_| "fixture retry failed")?;
    let stable_retry_id = prepared.intent.id == retry.intent.id;
    let prepared_only = prepared.intent.gateway == GatewayType::MycRail
        && prepared.intent.state == TransactionState::Initiated
        && prepared.intent.currency == "MYC"
        && prepared.intent.amount_micros == 10_000_000
        && !prepared.bank_posting_completed
        && prepared.intent.compliance_metadata["financial_state"] == "prepared_not_debited";
    let bank_posting_completed = prepared.bank_posting_completed;
    if !(w7_qa_ok
        && quote_roundtrip
        && signature_ok
        && wrong_pin_rejected
        && wrong_account_rejected
        && expired_rejected
        && tampered_quote_rejected
        && unsigned_quote_rejected
        && prepared_only
        && stable_retry_id
        && !bank_posting_completed)
    {
        return Err("W8 invariant failed");
    }
    Ok(PayLabReport {
        w7_qa_ok,
        quote_roundtrip,
        signature_ok,
        wrong_pin_rejected,
        wrong_account_rejected,
        expired_rejected,
        tampered_quote_rejected,
        unsigned_quote_rejected,
        prepared_only,
        stable_retry_id,
        bank_posting_completed,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn integrated_pay_lab() {
        let r = run_pay_lab().unwrap();
        assert!(
            r.w7_qa_ok
                && r.quote_roundtrip
                && r.signature_ok
                && r.prepared_only
                && r.stable_retry_id
        );
        assert!(!r.bank_posting_completed && !r.is_verified());
    }
    #[test]
    fn historical_quote_expired() {
        let q = quote().unwrap();
        assert!(q.verify(&q.merchant_xonly, EXPIRY).is_err());
        assert!(q.verify(&q.merchant_xonly, CLOCK - 1).is_err());
    }
    #[test]
    fn unrelated_quote_cannot_substitute_pin() {
        let a = quote().unwrap();
        let b = quote().unwrap();
        assert!(b.verify(&a.merchant_xonly, CLOCK + 1).is_err());
    }
    #[test]
    fn tampered_amount_rejected() {
        let mut q = quote().unwrap();
        q.usdc_reference_micros += 8;
        q.myc_to_pay_micros += 1;
        assert!(q.verify(&q.merchant_xonly, CLOCK + 1).is_err());
    }
}
