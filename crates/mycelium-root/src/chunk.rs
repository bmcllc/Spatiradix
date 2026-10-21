//! Pedaço = até 1 MiB de arquivo, cifrado e cortado em N fragmentos
//! Reed-Solomon (K de dados + N−K de paridade).

use crate::keys::Keys;
use crate::RootError;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use reed_solomon_erasure::galois_8::ReedSolomon;

pub const CHUNK_SIZE: usize = 1 << 20;
const MAGIC: &[u8; 4] = b"MRS1";
const HEADER: usize = 4 + 8 + 1 + 1 + 1;

/// Id do pedaço: MAC do texto claro (não vaza igualdade entre cofres).
pub fn chunk_id(keys: &Keys, plain: &[u8]) -> String {
    hex::encode(blake3::keyed_hash(&keys.mac, plain).as_bytes())
}

/// Cifra e codifica: devolve os N fragmentos (com cabeçalho) na ordem 1..=N.
pub fn encode(keys: &Keys, id: &str, plain: &[u8], k: u8, n: u8) -> Result<Vec<Vec<u8>>, RootError> {
    let cipher = XChaCha20Poly1305::new((&keys.chunk).into());
    let ct = cipher
        .encrypt(&nonce_for(keys, id), plain)
        .map_err(|_| RootError::Crypto)?;
    let (k_us, n_us) = (k as usize, n as usize);
    let shard_len = ct.len().div_ceil(k_us).max(1);
    let mut shards: Vec<Vec<u8>> = (0..n_us).map(|_| vec![0u8; shard_len]).collect();
    for (i, piece) in ct.chunks(shard_len).enumerate() {
        shards[i][..piece.len()].copy_from_slice(piece);
    }
    if n > k {
        let rs = ReedSolomon::new(k_us, n_us - k_us).map_err(|e| RootError::Msg(format!("rs: {e:?}")))?;
        rs.encode(&mut shards).map_err(|e| RootError::Msg(format!("rs: {e:?}")))?;
    }
    Ok(shards
        .into_iter()
        .enumerate()
        .map(|(i, body)| {
            let mut out = Vec::with_capacity(HEADER + body.len());
            out.extend_from_slice(MAGIC);
            out.extend_from_slice(&(ct.len() as u64).to_be_bytes());
            out.extend_from_slice(&[k, n, (i + 1) as u8]);
            out.extend_from_slice(&body);
            out
        })
        .collect())
}

/// Reconstrói o pedaço a partir dos fragmentos disponíveis (`None` = ausente).
/// Fragmento corrompido é detectado pela autenticação: tenta subconjuntos de
/// K fragmentos até um passar no AEAD e no MAC do id.
pub fn decode(keys: &Keys, id: &str, frags: &[Option<Vec<u8>>], k: u8, n: u8) -> Result<Vec<u8>, RootError> {
    let (k_us, n_us) = (k as usize, n as usize);
    // valida cabeçalhos; descarta o que não bate
    let mut parsed: Vec<Option<(u64, Vec<u8>)>> = vec![None; n_us];
    for (i, f) in frags.iter().enumerate().take(n_us) {
        let Some(f) = f else { continue };
        if f.len() < HEADER || &f[..4] != MAGIC || f[12] != k || f[13] != n || f[14] as usize != i + 1 {
            continue;
        }
        let mut len = [0u8; 8];
        len.copy_from_slice(&f[4..12]);
        parsed[i] = Some((u64::from_be_bytes(len), f[HEADER..].to_vec()));
    }
    let present: Vec<usize> = (0..n_us).filter(|&i| parsed[i].is_some()).collect();
    if present.len() < k_us {
        return Err(RootError::NotEnough {
            have: present.len(),
            need: k_us,
        });
    }
    let mut tried = 0usize;
    for subset in combinations(&present, k_us) {
        tried += 1;
        if tried > 512 {
            break;
        }
        if let Some(plain) = try_subset(keys, id, &parsed, &subset, k_us, n_us) {
            return Ok(plain);
        }
    }
    Err(RootError::Corrupt(id.to_string()))
}

fn try_subset(
    keys: &Keys,
    id: &str,
    parsed: &[Option<(u64, Vec<u8>)>],
    subset: &[usize],
    k: usize,
    n: usize,
) -> Option<Vec<u8>> {
    let first = parsed[subset[0]].as_ref()?;
    let (ct_len, shard_len) = (first.0, first.1.len());
    let mut shards: Vec<Option<Vec<u8>>> = vec![None; n];
    for &i in subset {
        let (l, body) = parsed[i].as_ref()?;
        if *l != ct_len || body.len() != shard_len {
            return None;
        }
        shards[i] = Some(body.clone());
    }
    if n > k {
        let rs = ReedSolomon::new(k, n - k).ok()?;
        rs.reconstruct_data(&mut shards).ok()?;
    }
    let mut ct = Vec::with_capacity(k * shard_len);
    for s in shards.iter().take(k) {
        ct.extend_from_slice(s.as_ref()?);
    }
    ct.truncate(usize::try_from(ct_len).ok()?);
    let cipher = XChaCha20Poly1305::new((&keys.chunk).into());
    let plain = cipher.decrypt(&nonce_for(keys, id), ct.as_slice()).ok()?;
    (chunk_id(keys, &plain) == id).then_some(plain)
}

fn nonce_for(keys: &Keys, id: &str) -> XNonce {
    let mut h = blake3::Hasher::new_keyed(&keys.mac);
    h.update(b"mycelium-root/nonce/v1");
    h.update(id.as_bytes());
    let out = h.finalize();
    *XNonce::from_slice(&out.as_bytes()[..24])
}

fn combinations(items: &[usize], k: usize) -> Vec<Vec<usize>> {
    let mut out = Vec::new();
    let mut cur = Vec::with_capacity(k);
    fn rec(items: &[usize], k: usize, start: usize, cur: &mut Vec<usize>, out: &mut Vec<Vec<usize>>) {
        if cur.len() == k {
            out.push(cur.clone());
            return;
        }
        for i in start..items.len() {
            cur.push(items[i]);
            rec(items, k, i + 1, cur, out);
            cur.pop();
            if out.len() > 512 {
                return;
            }
        }
    }
    rec(items, k, 0, &mut cur, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn any_k_of_n_and_corruption() {
        let keys = Keys::derive(&[7u8; 32]);
        let data: Vec<u8> = (0..3000u32).map(|i| (i * 31) as u8).collect();
        let id = chunk_id(&keys, &data);
        let frags = encode(&keys, &id, &data, 2, 4).unwrap();
        // quaisquer 2 dos 4
        for a in 0..4 {
            for b in (a + 1)..4 {
                let mut v: Vec<Option<Vec<u8>>> = vec![None; 4];
                v[a] = Some(frags[a].clone());
                v[b] = Some(frags[b].clone());
                assert_eq!(decode(&keys, &id, &v, 2, 4).unwrap(), data, "{a},{b}");
            }
        }
        // 1 só: insuficiente
        let mut one: Vec<Option<Vec<u8>>> = vec![None; 4];
        one[2] = Some(frags[2].clone());
        assert!(matches!(decode(&keys, &id, &one, 2, 4), Err(RootError::NotEnough { .. })));
        // um fragmento corrompido entre 3: ainda reconstrói pelos outros 2
        let mut bad: Vec<Option<Vec<u8>>> = frags.iter().cloned().map(Some).collect();
        bad[3] = None;
        let mut c = frags[0].clone();
        let last = c.len() - 1;
        c[last] ^= 0xff;
        bad[0] = Some(c);
        assert_eq!(decode(&keys, &id, &bad, 2, 4).unwrap(), data);
        // chave errada não abre
        let other = Keys::derive(&[8u8; 32]);
        let all: Vec<Option<Vec<u8>>> = frags.iter().cloned().map(Some).collect();
        assert!(decode(&other, &id, &all, 2, 4).is_err());
    }
}
