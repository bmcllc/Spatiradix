//! Syntax-level SWIFT/ISO 9362 helpers, not network certification or BIC registry validation.

/// Matches the BIC textual layout 4!a2!a2!c[3!c] used in SWIFT MT documentation.
/// Registry membership and institution eligibility must be checked separately.
pub fn bic_has_valid_syntax(bic: &str) -> bool {
    let b = bic.as_bytes();
    (b.len() == 8 || b.len() == 11)
        && b[..4].iter().all(u8::is_ascii_uppercase)
        && b[4..6].iter().all(u8::is_ascii_uppercase)
        && b[6..].iter().all(u8::is_ascii_alphanumeric)
        && !b.iter().any(u8::is_ascii_lowercase)
}

/// Derive a stable UUIDv4-layout UETR from the unique local payment-intent bytes.
/// The local identifier must have unique entropy; this does not register a SWIFT transaction.
pub fn uetr_from_intent(canonical: &[u8]) -> String {
    let mut u = [0u8; 16];
    u.copy_from_slice(&blake3::hash(canonical).as_bytes()[..16]);
    u[6] = (u[6] & 0x0F) | 0x40;
    u[8] = (u[8] & 0x3F) | 0x80;
    format!(
        "{}-{}-{}-{}-{}",
        hex::encode(&u[..4]),
        hex::encode(&u[4..6]),
        hex::encode(&u[6..8]),
        hex::encode(&u[8..10]),
        hex::encode(&u[10..]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bic_rejects_malformed_or_xml_injection() {
        assert!(bic_has_valid_syntax("CHASUS33"));
        assert!(bic_has_valid_syntax("CHASUS33XXX"));
        for bad in [
            "CHASUS3",
            "CHASUS33XXXX",
            "chasus33xxx",
            "1234US33XXX",
            "CHASU133XXX",
            "CHASUS3<XXX",
        ] {
            assert!(!bic_has_valid_syntax(bad), "{bad}");
        }
    }

    #[test]
    fn uetr_has_version_4_and_rfc_variant_bits() {
        let uetr = uetr_from_intent(b"a-unique-payment-intent");
        assert_eq!(uetr.len(), 36);
        assert_eq!(uetr.as_bytes()[14], b'4');
        assert!(b"89ab".contains(&uetr.as_bytes()[19]));
        assert_eq!(uetr, uetr_from_intent(b"a-unique-payment-intent"));
        assert_ne!(uetr, uetr_from_intent(b"a-different-payment-intent"));
    }
}
