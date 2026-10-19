//! z-base-32 (alfabeto do Pkarr): 32 bytes de chave ↔ 52 caracteres.

const ALPHABET: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for &b in bytes {
        buffer = (buffer << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

/// Decodifica exatamente `N` bytes. Recusa caractere fora do alfabeto,
/// comprimento errado e bits de enchimento não-nulos (forma canônica única,
/// para que duas strings diferentes nunca apontem para a mesma chave).
pub fn decode<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != (N * 8).div_ceil(5) {
        return None;
    }
    let mut out = [0u8; N];
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    let mut idx = 0usize;
    for c in s.bytes() {
        let v = ALPHABET.iter().position(|&a| a == c)? as u32;
        buffer = (buffer << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out[idx] = (buffer >> bits) as u8;
            idx += 1;
            buffer &= (1 << bits) - 1;
        }
    }
    if idx != N || buffer != 0 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_canonical() {
        let key = [0xabu8; 32];
        let s = encode(&key);
        assert_eq!(s.len(), 52);
        assert_eq!(decode::<32>(&s), Some(key));
        // último caractere com bits de enchimento ≠ 0 → recusado
        let last = s.as_bytes()[51];
        let v = ALPHABET.iter().position(|&a| a == last).unwrap();
        let mut bad = s[..51].to_string();
        bad.push(ALPHABET[v ^ 1] as char);
        assert!(decode::<32>(&bad).is_none());
        assert!(decode::<32>("curto").is_none());
        assert!(decode::<32>(&s.to_uppercase()).is_none());
    }
}
