//! W7: local privacy/integrity self-test for a fixed synthetic QA report.
//! No payment data, credentials, network routes, storage or ledger changes.
use crate::bse_web_psp_lab::{run_lab, LabReport};
use mycelium_qel::{fragment, reconstruct, QelConfig, QelShard};
use mycelium_veil::crypto::{HopDecryptor, HopEncryptor};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroizing;

const DOMAIN: &[u8] = b"BSE-W7-LAB-QA-v1:";
const THRESHOLD: usize = 3;
const TOTAL: usize = 5;
type R<T> = Result<T, &'static str>;

/// Fixed-format aggregate QA flags only; no balances, keys, references or payloads.
fn qa_flags(r: &LabReport) -> [u8; 11] {
    [
        r.directory_ok,
        r.idempotency_ok,
        r.simulated_transfer_ok,
        r.insufficient_credits_rejected,
        r.duplicate_prevented,
        r.cancel_ok,
        r.conserved,
        r.w1_fixture_ok,
        r.w2_fixture_ok,
        r.w3_fixture_ok,
        r.w5_fixture_ok,
    ]
    .map(u8::from)
}
fn fixture() -> R<Vec<u8>> {
    let r = run_lab().map_err(|_| "W6 lab failed")?;
    let flags = qa_flags(&r);
    if flags.iter().any(|x| *x != 1) {
        return Err("W6 QA flag failed");
    }
    let mut data = DOMAIN.to_vec();
    data.extend_from_slice(&flags);
    Ok(data)
}
fn new_key() -> R<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    OsRng
        .try_fill_bytes(&mut *key)
        .map_err(|_| "OS randomness unavailable")?;
    Ok(key)
}
fn split_ciphertext(ciphertext: &[u8]) -> R<Vec<QelShard>> {
    // Unique local content identifier, derived from ciphertext, never from user data.
    let id = format!("bse-w7-lab:{}", blake3::hash(ciphertext).to_hex());
    fragment(
        ciphertext,
        &id,
        &QelConfig {
            threshold: THRESHOLD as u8,
            total: TOTAL as u8,
            ttl_secs: 60,
        },
    )
    .map_err(|_| "QEL fragmentation failed")
}
#[derive(Debug, PartialEq, Eq)]
pub struct PrivacyLabReport {
    pub qa_flags: usize,
    pub threshold: usize,
    pub total_shards: usize,
    pub combinations_checked: usize,
    pub encrypted_roundtrip: bool,
    pub insufficient_rejected: bool,
    pub duplicate_rejected: bool,
    pub tamper_rejected: bool,
    pub replay_rejected: bool,
    pub wrong_key_rejected: bool,
    pub mixed_sets_rejected: bool,
}
impl PrivacyLabReport {
    pub const fn is_verified(&self) -> bool {
        false
    }
}
/// Only fixed W6 QA data enters this function. All crypto/shares stay in RAM.
/// No reusable encrypt/decrypt endpoint, payment payloads or transport.
pub fn run_privacy_lab() -> R<PrivacyLabReport> {
    let plain = Zeroizing::new(fixture()?);
    let key = new_key()?;
    let mut enc = HopEncryptor::new(&key);
    let cipher = enc.encrypt(&plain).map_err(|_| "VEIL encryption failed")?;
    let shards = split_ciphertext(&cipher)?;
    if shards.len() != TOTAL {
        return Err("unexpected QEL share count");
    }
    let mut combinations_checked = 0;
    for a in 0..TOTAL {
        for b in a + 1..TOTAL {
            for c in b + 1..TOTAL {
                let recovered =
                    reconstruct(&[shards[a].clone(), shards[b].clone(), shards[c].clone()])
                        .map_err(|_| "QEL reconstruction failed")?;
                if recovered != cipher {
                    return Err("QEL reconstruction mismatch");
                }
                let mut dec = HopDecryptor::new(&key);
                let data = Zeroizing::new(
                    dec.decrypt(&recovered)
                        .map_err(|_| "VEIL authentication failed")?,
                );
                if data.as_slice() != plain.as_slice() {
                    return Err("QA report mismatch");
                }
                combinations_checked += 1;
            }
        }
    }
    let insufficient_rejected = reconstruct(&shards[..THRESHOLD - 1]).is_err();
    let duplicate_rejected =
        reconstruct(&[shards[0].clone(), shards[0].clone(), shards[1].clone()]).is_err();
    let mut damaged = cipher.clone();
    *damaged.last_mut().ok_or("empty ciphertext")? ^= 1;
    let mut dec = HopDecryptor::new(&key);
    let tamper_rejected = dec.decrypt(&damaged).is_err();
    let recovered = Zeroizing::new(
        dec.decrypt(&cipher)
            .map_err(|_| "valid ciphertext rejected")?,
    );
    let encrypted_roundtrip = recovered.as_slice() == plain.as_slice();
    let replay_rejected = dec.decrypt(&cipher).is_err();
    let mut wrong = Zeroizing::new(*key);
    wrong[0] ^= 1;
    let wrong_key_rejected = HopDecryptor::new(&wrong).decrypt(&cipher).is_err();
    let second = enc.encrypt(&plain).map_err(|_| "VEIL encryption failed")?;
    let other = split_ciphertext(&second)?;
    let mixed_sets_rejected =
        reconstruct(&[shards[0].clone(), shards[1].clone(), other[2].clone()]).is_err();
    if !(encrypted_roundtrip
        && insufficient_rejected
        && duplicate_rejected
        && tamper_rejected
        && replay_rejected
        && wrong_key_rejected
        && mixed_sets_rejected
        && combinations_checked == 10)
    {
        return Err("privacy lab invariant failed");
    }
    Ok(PrivacyLabReport {
        qa_flags: 11,
        threshold: THRESHOLD,
        total_shards: TOTAL,
        combinations_checked,
        encrypted_roundtrip,
        insufficient_rejected,
        duplicate_rejected,
        tamper_rejected,
        replay_rejected,
        wrong_key_rejected,
        mixed_sets_rejected,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn privacy_lab_full() {
        let r = run_privacy_lab().unwrap();
        assert_eq!(
            (r.threshold, r.total_shards, r.combinations_checked),
            (3, 5, 10)
        );
        assert!(
            r.encrypted_roundtrip
                && r.insufficient_rejected
                && r.duplicate_rejected
                && r.tamper_rejected
                && r.replay_rejected
                && r.wrong_key_rejected
                && r.mixed_sets_rejected
        );
        assert!(!r.is_verified());
    }
    #[test]
    fn fixture_minimization() {
        let d = fixture().unwrap();
        assert_eq!(&d[..DOMAIN.len()], DOMAIN);
        assert_eq!(&d[DOMAIN.len()..], &[1; 11]);
    }
    #[test]
    fn fixed_flags_no_balance() {
        let mut r = run_lab().unwrap();
        let a = qa_flags(&r);
        r.buyer_credits = 0;
        r.merchant_credits = u64::MAX;
        assert_eq!(a, qa_flags(&r));
    }
}
