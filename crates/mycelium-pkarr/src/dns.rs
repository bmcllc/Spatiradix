//! Pacote DNS mínimo (RFC 1035) só com registros TXT — o suficiente para o
//! payload do Pkarr. Escrito à mão para manter a superfície de parsing de
//! dados não confiáveis pequena e com limites explícitos.

use crate::PkarrError;

const TYPE_TXT: u16 = 16;
const CLASS_IN: u16 = 1;
const MAX_POINTER_JUMPS: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxtRecord {
    /// Nome completo, em minúsculas, sem ponto final (ex.: `_myc.<z32>`).
    pub name: String,
    pub ttl: u32,
    /// Character-strings do TXT (cada uma ≤ 255 bytes, binário permitido).
    pub strings: Vec<Vec<u8>>,
}

/// Divide `data` em character-strings de até 255 bytes.
pub fn split_txt(data: &[u8]) -> Vec<Vec<u8>> {
    data.chunks(255).map(<[u8]>::to_vec).collect()
}

pub fn encode(records: &[TxtRecord]) -> Result<Vec<u8>, PkarrError> {
    let ancount = u16::try_from(records.len()).map_err(|_| PkarrError::Dns("registros demais"))?;
    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(&0u16.to_be_bytes()); // id
    out.extend_from_slice(&0x8400u16.to_be_bytes()); // QR=1 (resposta), AA=1
    out.extend_from_slice(&0u16.to_be_bytes()); // qdcount
    out.extend_from_slice(&ancount.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // nscount
    out.extend_from_slice(&0u16.to_be_bytes()); // arcount
    for r in records {
        encode_name(&r.name, &mut out)?;
        out.extend_from_slice(&TYPE_TXT.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&r.ttl.to_be_bytes());
        let rdlen: usize = r.strings.iter().map(|s| 1 + s.len()).sum();
        let rdlen = u16::try_from(rdlen).map_err(|_| PkarrError::Dns("rdata grande demais"))?;
        out.extend_from_slice(&rdlen.to_be_bytes());
        for s in &r.strings {
            let len = u8::try_from(s.len()).map_err(|_| PkarrError::Dns("string TXT > 255"))?;
            out.push(len);
            out.extend_from_slice(s);
        }
    }
    Ok(out)
}

fn encode_name(name: &str, out: &mut Vec<u8>) -> Result<(), PkarrError> {
    if name.len() > 253 {
        return Err(PkarrError::Dns("nome longo demais"));
    }
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(PkarrError::Dns("rótulo inválido"));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

/// Lê todos os TXT da seção de respostas. Registros de outros tipos são
/// ignorados; qualquer byte fora dos limites é erro (nunca pânico).
pub fn decode_txt(packet: &[u8]) -> Result<Vec<TxtRecord>, PkarrError> {
    let mut r = Reader {
        buf: packet,
        pos: 0,
    };
    r.take(4)?; // id + flags
    let qdcount = r.u16()?;
    let ancount = r.u16()?;
    r.take(4)?; // ns + ar
    for _ in 0..qdcount {
        read_name(packet, &mut r.pos)?;
        r.take(4)?;
    }
    let mut out = Vec::new();
    for _ in 0..ancount {
        let name = read_name(packet, &mut r.pos)?;
        let rtype = r.u16()?;
        let _class = r.u16()?;
        let ttl = r.u32()?;
        let rdlen = r.u16()? as usize;
        let rdata = r.take(rdlen)?;
        if rtype != TYPE_TXT {
            continue;
        }
        let mut strings = Vec::new();
        let mut i = 0usize;
        while i < rdata.len() {
            let len = rdata[i] as usize;
            let s = rdata
                .get(i + 1..i + 1 + len)
                .ok_or(PkarrError::Dns("string TXT truncada"))?;
            strings.push(s.to_vec());
            i += 1 + len;
        }
        out.push(TxtRecord { name, ttl, strings });
    }
    Ok(out)
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], PkarrError> {
        let end = self.pos.checked_add(n).ok_or(PkarrError::Dns("overflow"))?;
        let s = self
            .buf
            .get(self.pos..end)
            .ok_or(PkarrError::Dns("pacote truncado"))?;
        self.pos = end;
        Ok(s)
    }
    fn u16(&mut self) -> Result<u16, PkarrError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Result<u32, PkarrError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
}

/// Lê um nome com suporte a ponteiros de compressão (limitado contra laços).
fn read_name(buf: &[u8], pos: &mut usize) -> Result<String, PkarrError> {
    let mut labels: Vec<String> = Vec::new();
    let mut cursor = *pos;
    let mut jumped = false;
    let mut jumps = 0usize;
    loop {
        let len = *buf.get(cursor).ok_or(PkarrError::Dns("nome truncado"))? as usize;
        if len & 0xc0 == 0xc0 {
            let lo = *buf
                .get(cursor + 1)
                .ok_or(PkarrError::Dns("ponteiro truncado"))? as usize;
            if !jumped {
                *pos = cursor + 2;
            }
            jumped = true;
            jumps += 1;
            if jumps > MAX_POINTER_JUMPS {
                return Err(PkarrError::Dns("laço de ponteiros"));
            }
            cursor = ((len & 0x3f) << 8) | lo;
            continue;
        }
        if len & 0xc0 != 0 {
            return Err(PkarrError::Dns("tipo de rótulo desconhecido"));
        }
        if len == 0 {
            if !jumped {
                *pos = cursor + 1;
            }
            break;
        }
        let label = buf
            .get(cursor + 1..cursor + 1 + len)
            .ok_or(PkarrError::Dns("rótulo truncado"))?;
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        cursor += 1 + len;
        if labels.iter().map(|l| l.len() + 1).sum::<usize>() > 255 {
            return Err(PkarrError::Dns("nome longo demais"));
        }
    }
    Ok(labels.join("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_binary_txt() {
        let data: Vec<u8> = (0..=255u8).cycle().take(600).collect();
        let rec = TxtRecord {
            name: "_myc.abc".into(),
            ttl: 300,
            strings: split_txt(&data),
        };
        let pkt = encode(std::slice::from_ref(&rec)).unwrap();
        let back = decode_txt(&pkt).unwrap();
        assert_eq!(back, vec![rec]);
    }

    #[test]
    fn garbage_never_panics() {
        for len in 0..64 {
            let junk: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let _ = decode_txt(&junk);
        }
        // ponteiro apontando para si mesmo
        let mut pkt = vec![0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        pkt.extend_from_slice(&[0xc0, 12]);
        assert!(decode_txt(&pkt).is_err());
    }
}
