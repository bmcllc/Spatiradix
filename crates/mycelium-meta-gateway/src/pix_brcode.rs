//! Pix dynamic BR Code builder, per Manual de Padrões para Iniciação do Pix v2.10.0, section 2.7.
//! This function NEVER performs a PSP call. The PSP-issued location must first be authenticated.

use crate::error::GatewayError;

/// Serialize a BR Code TLV (ASCII only, a two-digit byte length).
fn tlv(id: &str, value: &str) -> String {
    format!("{id}{:02}{value}", value.len())
}

fn crc16_ccitt(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

/// Build a dynamic Pix BR Code from a validated, PSP-issued location.
/// Passing a syntactically valid location does NOT prove that it belongs to a trusted PSP.
pub fn build_dynamic_emv_brcode(
    location: &str,
    merchant_name: &str,
    merchant_city: &str,
) -> Result<String, GatewayError> {
    let url = location.trim();
    let Some((host, resource)) = url.split_once('/') else {
        return Err(GatewayError::InvalidTarget(
            "Pix location is missing its resource".into(),
        ));
    };
    let valid_host = host.contains('.')
        && host.split('.').all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    if !(1..=77).contains(&url.len())
        || !url.is_ascii()
        || host.parse::<std::net::Ipv4Addr>().is_ok()
        || !valid_host
        || resource.is_empty()
        || !resource
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~/".contains(&b))
    {
        return Err(GatewayError::InvalidTarget(
            "Pix location is not a BR Code 26.25 address".into(),
        ));
    }
    let name = merchant_name.trim();
    let city = merchant_city.trim();
    if name.is_empty()
        || name.len() > 25
        || !name.is_ascii()
        || city.is_empty()
        || city.len() > 15
        || !city.is_ascii()
    {
        return Err(GatewayError::InvalidTarget(
            "Pix merchant name or city violates length/charset constraints".into(),
        ));
    }
    let mai = tlv(
        "26",
        &format!("{}{}", tlv("00", "br.gov.bcb.pix"), tlv("25", url)),
    );
    let body = format!(
        "{}{}{}{}{}{}{}{}{}6304",
        tlv("00", "01"),
        tlv("01", "12"),
        mai,
        tlv("52", "0000"),
        tlv("53", "986"),
        tlv("58", "BR"),
        tlv("59", name),
        tlv("60", city),
        tlv("62", &tlv("05", "***")),
    );
    Ok(format!("{body}{:04X}", crc16_ccitt(body.as_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_dynamic_pix_qr_matches_manual_example_crc() {
        let location = "pix.example.com/8b3da2f39a4140d1a91abd93113bd441";
        let qr = build_dynamic_emv_brcode(location, "Fulano de Tal", "BRASILIA").unwrap();
        assert_eq!(qr, "00020101021226700014br.gov.bcb.pix2548pix.example.com/8b3da2f39a4140d1a91abd93113bd4415204000053039865802BR5913Fulano de Tal6008BRASILIA62070503***630464E4");
    }

    #[test]
    fn rejects_bad_locations_without_fetching_them() {
        for location in [
            "https://pix.example.com/x",
            "http://pix.example.com/x",
            "pix.example.com",
            "127.0.0.1/x",
            "pix.example.com/",
            "pix.example.com/x?token=1",
        ] {
            assert!(
                build_dynamic_emv_brcode(location, "Fulano", "BRASILIA").is_err(),
                "{location}"
            );
        }
        let too_long = format!("pix.example.com/{}", "a".repeat(90));
        assert!(build_dynamic_emv_brcode(&too_long, "Fulano", "BRASILIA").is_err());
    }
}
