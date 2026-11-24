//! CBOR determinístico (RFC 8949 §4.2.1), só o subconjunto do envelope v1:
//! uint, bstr, tstr (UTF-8), array, map com chaves uint. Sem floats, tags, nem comprimento indefinido.
//! O decodificador rejeita qualquer forma não-canônica.

use crate::PayError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Uint(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    /// Chaves estritamente crescentes (garantido por `decode`; `encode` ordena e rejeita duplicatas).
    Map(Vec<(u64, Value)>),
}

const MAX_DEPTH: u32 = 8;

fn head(out: &mut Vec<u8>, major: u8, n: u64) {
    let m = major << 5;
    match n {
        0..=23 => out.push(m | n as u8),
        24..=0xff => out.extend([m | 24, n as u8]),
        0x100..=0xffff => {
            out.push(m | 25);
            out.extend((n as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(m | 26);
            out.extend((n as u32).to_be_bytes());
        }
        _ => {
            out.push(m | 27);
            out.extend(n.to_be_bytes());
        }
    }
}

pub fn encode(v: &Value) -> Result<Vec<u8>, PayError> {
    let mut out = vec![];
    enc(v, &mut out)?;
    Ok(out)
}

fn enc(v: &Value, out: &mut Vec<u8>) -> Result<(), PayError> {
    match v {
        Value::Uint(n) => head(out, 0, *n),
        Value::Bytes(b) => {
            head(out, 2, b.len() as u64);
            out.extend(b);
        }
        Value::Text(t) => {
            head(out, 3, t.len() as u64);
            out.extend(t.as_bytes());
        }
        Value::Array(a) => {
            head(out, 4, a.len() as u64);
            for x in a {
                enc(x, out)?;
            }
        }
        Value::Map(m) => {
            let mut keys: Vec<_> = m.iter().collect();
            keys.sort_by_key(|(k, _)| *k);
            if keys.windows(2).any(|w| w[0].0 == w[1].0) {
                return Err(PayError::Cbor("chave de mapa duplicada"));
            }
            head(out, 5, m.len() as u64);
            for (k, x) in keys {
                head(out, 0, *k);
                enc(x, out)?;
            }
        }
    }
    Ok(())
}

pub fn decode(buf: &[u8]) -> Result<Value, PayError> {
    let mut pos = 0;
    let v = dec(buf, &mut pos, 0)?;
    if pos != buf.len() {
        return Err(PayError::Cbor("bytes sobrando após o item"));
    }
    Ok(v)
}

fn take<'a>(buf: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], PayError> {
    let end = pos.checked_add(n).filter(|e| *e <= buf.len()).ok_or(PayError::Cbor("truncado"))?;
    let s = &buf[*pos..end];
    *pos = end;
    Ok(s)
}

fn dec(buf: &[u8], pos: &mut usize, depth: u32) -> Result<Value, PayError> {
    if depth > MAX_DEPTH {
        return Err(PayError::Cbor("aninhamento excessivo"));
    }
    let b = take(buf, pos, 1)?[0];
    let (major, ai) = (b >> 5, b & 31);
    let (n, min) = match ai {
        0..=23 => (ai as u64, 0),
        24 => (take(buf, pos, 1)?[0] as u64, 24),
        25 => (u16::from_be_bytes(take(buf, pos, 2)?.try_into().unwrap()) as u64, 0x100),
        26 => (u32::from_be_bytes(take(buf, pos, 4)?.try_into().unwrap()) as u64, 0x1_0000),
        27 => (u64::from_be_bytes(take(buf, pos, 8)?.try_into().unwrap()), 0x1_0000_0000),
        _ => return Err(PayError::Cbor("comprimento indefinido ou reservado")),
    };
    if n < min {
        return Err(PayError::Cbor("inteiro não está na forma mais curta"));
    }
    match major {
        0 => Ok(Value::Uint(n)),
        2 => Ok(Value::Bytes(take(buf, pos, usize::try_from(n).map_err(|_| PayError::Cbor("tamanho"))?)?.to_vec())),
        3 => {
            let b = take(buf, pos, usize::try_from(n).map_err(|_| PayError::Cbor("tamanho"))?)?;
            String::from_utf8(b.to_vec()).map(Value::Text).map_err(|_| PayError::Cbor("texto não é UTF-8"))
        }
        4 => {
            // cada item ocupa ≥1 byte: n > restante é truncado, e evita alocação gigante
            if n > (buf.len() - *pos) as u64 {
                return Err(PayError::Cbor("truncado"));
            }
            (0..n).map(|_| dec(buf, pos, depth + 1)).collect::<Result<_, _>>().map(Value::Array)
        }
        5 => {
            if n > (buf.len() - *pos) as u64 / 2 {
                return Err(PayError::Cbor("truncado"));
            }
            let mut m: Vec<(u64, Value)> = Vec::with_capacity(n as usize);
            for _ in 0..n {
                let Value::Uint(k) = dec(buf, pos, depth + 1)? else {
                    return Err(PayError::Cbor("chave de mapa não é inteiro"));
                };
                if m.last().is_some_and(|(p, _)| *p >= k) {
                    return Err(PayError::Cbor("chaves fora de ordem ou duplicadas"));
                }
                m.push((k, dec(buf, pos, depth + 1)?));
            }
            Ok(Value::Map(m))
        }
        _ => Err(PayError::Cbor("tipo CBOR não permitido (negativo, tag, float)")),
    }
}
