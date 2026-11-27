//! Offline BR Code structural inspection (Pix manual v2.10.0).
//! No DICT lookup, URL fetch, authorization or settlement is performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixKind {
    Static,
    Dynamic,
    Compound,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inspection {
    pub kind: PixKind,
    pub amount_cents: Option<u64>,
    pub txid: Option<String>,
    pub has_payment: bool,
    pub has_recurrence: bool,
}
fn crc16(bytes: &[u8]) -> u16 {
    let mut crc = 0xffffu16;
    for &b in bytes {
        crc ^= (b as u16) << 8;
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
fn fields(input: &str) -> Result<Vec<(u8, &str)>, &'static str> {
    if !input.is_ascii() || input.bytes().any(|b| b.is_ascii_control()) {
        return Err("unsupported character");
    }
    let mut rest = input;
    let mut out = Vec::new();
    while !rest.is_empty() {
        if rest.len() < 4 || !rest.as_bytes()[..4].iter().all(u8::is_ascii_digit) {
            return Err("invalid TLV header");
        }
        let tag: u8 = rest[..2].parse().map_err(|_| "invalid tag")?;
        let len: usize = rest[2..4].parse().map_err(|_| "invalid length")?;
        if len == 0 || rest.len() < 4 + len {
            return Err("invalid TLV length");
        }
        if out.iter().any(|(t, _)| *t == tag) {
            return Err("duplicate tag");
        }
        out.push((tag, &rest[4..4 + len]));
        rest = &rest[4 + len..];
    }
    Ok(out)
}
fn get<'a>(f: &[(u8, &'a str)], tag: u8) -> Option<&'a str> {
    f.iter().find(|(t, _)| *t == tag).map(|(_, v)| *v)
}
fn cents(s: &str) -> Result<u64, &'static str> {
    let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
    if whole.is_empty()
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || frac.len() > 2
        || (s.contains('.') && frac.is_empty())
        || !frac.bytes().all(|b| b.is_ascii_digit())
    {
        return Err("invalid amount");
    }
    let w: u64 = whole.parse().map_err(|_| "invalid amount")?;
    let f: u64 = if frac.is_empty() {
        0
    } else {
        frac.parse().map_err(|_| "invalid amount")?
    };
    let n = w
        .checked_mul(100)
        .and_then(|x| x.checked_add(if frac.len() == 1 { f * 10 } else { f }))
        .ok_or("amount overflow")?;
    if n == 0 {
        return Err("zero amount");
    }
    Ok(n)
}
/// Structural inspection only: a valid checksum is not proof of authenticity.
pub fn inspect_pix(input: &str) -> Result<Inspection, &'static str> {
    if input.len() > 4096 || input.len() < 8 || !input.is_ascii() {
        return Err("invalid payload size or encoding");
    }
    let f = fields(input)?;
    if f.first() != Some(&(0, "01")) || f.last().map(|x| x.0) != Some(63) {
        return Err("invalid envelope");
    }
    let check = get(&f, 63).ok_or("missing CRC")?;
    if check.len() != 4
        || !check.bytes().all(|b| b.is_ascii_hexdigit())
        || u16::from_str_radix(check, 16).ok() != Some(crc16(&input.as_bytes()[..input.len() - 4]))
    {
        return Err("CRC mismatch");
    }
    if get(&f, 53) != Some("986") || get(&f, 58) != Some("BR") {
        return Err("not BRL/BR");
    }
    let mut payment = None;
    let mut payment_template_seen = false;
    let mut empty_pix_template = false;
    let mut recurrence = false;
    for &(tag, value) in &f {
        if !(26..=51).contains(&tag) && !(80..=99).contains(&tag) {
            continue;
        }
        let inner = fields(value)?;
        if !get(&inner, 0).is_some_and(|s| s.eq_ignore_ascii_case("br.gov.bcb.pix")) {
            continue;
        }
        if (26..=51).contains(&tag) {
            if payment_template_seen {
                return Err("ambiguous Pix payment");
            }
            payment_template_seen = true;
            if inner.len() == 1 && get(&inner, 0).is_some() {
                empty_pix_template = true;
                continue;
            }
            if get(&inner, 3).is_some() {
                return Err("Pix Saque not supported by this inspector");
            }
            payment = Some(match (get(&inner, 1), get(&inner, 25)) {
                (Some(k), None) if k.len() <= 77 => PixKind::Static,
                (None, Some(u)) if u.len() <= 77 => PixKind::Dynamic,
                _ => return Err("invalid Pix payment template"),
            });
        } else {
            if recurrence || !get(&inner, 25).is_some_and(|u| u.len() <= 77) {
                return Err("invalid recurrence template");
            }
            recurrence = true;
        }
    }
    if (empty_pix_template && !recurrence) || (payment.is_none() && !recurrence) {
        return Err("no Pix template");
    }
    let (amount_cents, txid) = if payment == Some(PixKind::Static) {
        let amount = get(&f, 54).map(cents).transpose()?;
        let add = fields(get(&f, 62).ok_or("missing additional data")?)?;
        let t = get(&add, 5).ok_or("missing reference label")?;
        let tx = if t == "***" {
            None
        } else if t.len() <= 25 && t.bytes().all(|b| b.is_ascii_alphanumeric()) {
            Some(t.to_owned())
        } else {
            return Err("invalid static txid");
        };
        (amount, tx)
    } else {
        (None, None)
    };
    Ok(Inspection {
        kind: if recurrence {
            PixKind::Compound
        } else {
            payment.ok_or("missing payment")?
        },
        amount_cents,
        txid,
        has_payment: payment.is_some(),
        has_recurrence: recurrence,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    const STATIC: &str="00020126580014br.gov.bcb.pix0136123e4567-e12b-12d1-a456-4266554400005204000053039865802BR5913Fulano de Tal6008BRASILIA62070503***63041D3D";
    const DYNAMIC: &str="00020101021226700014br.gov.bcb.pix2548pix.example.com/8b3da2f39a4140d1a91abd93113bd4415204000053039865802BR5913Fulano de Tal6008BRASILIA62070503***630464E4";
    fn with_crc(body: &str) -> String {
        format!("{body}{:04X}", crc16(body.as_bytes()))
    }
    #[test]
    fn manual_static() {
        let x = inspect_pix(STATIC).unwrap();
        assert_eq!(x.kind, PixKind::Static);
        assert_eq!(x.amount_cents, None);
        assert_eq!(x.txid, None);
    }
    #[test]
    fn manual_dynamic() {
        let x = inspect_pix(DYNAMIC).unwrap();
        assert_eq!(x.kind, PixKind::Dynamic);
        assert_eq!(x.amount_cents, None);
    }
    #[test]
    fn rejects_bad_crc() {
        assert!(inspect_pix(&STATIC.replace("BRASILIA", "FORTALEZ")).is_err());
    }
    #[test]
    fn rejects_truncation_and_duplicate() {
        assert!(inspect_pix(&STATIC[..STATIC.len() - 1]).is_err());
        let body = format!("{}53039866304", &STATIC[..STATIC.len() - 8]);
        assert!(inspect_pix(&with_crc(&body)).is_err());
    }
    #[test]
    fn dynamic_ignores_outer_values() {
        let b = DYNAMIC
            .replace("5802BR", "54041.005802BR")
            .replace("0503***", "0503ABC");
        let b = with_crc(&b[..b.len() - 4]);
        let x = inspect_pix(&b).unwrap();
        assert_eq!((x.amount_cents, x.txid), (None, None));
    }
    #[test]
    fn static_amount_and_txid() {
        let b = STATIC
            .replace("5802BR", "540512.345802BR")
            .replace("0503***", "0503ABC");
        let b = with_crc(&b[..b.len() - 4]);
        let x = inspect_pix(&b).unwrap();
        assert_eq!(x.amount_cents, Some(1234));
        assert_eq!(x.txid.as_deref(), Some("ABC"));
    }
    #[test]
    fn official_recurrence_only() {
        let x = inspect_pix("00020126180014br.gov.bcb.pix5204000053039865802BR5913Fulano de Tal6008BRASILIA62070503***80740014br.gov.bcb.pix2552pix.example.com/rec/2353c790eefb11eaadc10242ac1200026304F2DA").unwrap();
        assert_eq!(x.kind, PixKind::Compound);
        assert!(!x.has_payment);
    }
    #[test]
    fn recurrence_only() {
        let b =
            with_crc("00020153039865802BR5904TEST6004CITY80290014br.gov.bcb.pix2507x.t/rec6304");
        let x = inspect_pix(&b).unwrap();
        assert_eq!(x.kind, PixKind::Compound);
        assert!(!x.has_payment);
        assert!(x.has_recurrence);
    }
}
