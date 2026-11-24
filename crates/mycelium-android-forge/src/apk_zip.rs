use crc32fast::Hasher as Crc32;
use flate2::{write::DeflateEncoder, Compression};
use std::io::Write;

#[derive(Debug, thiserror::Error)]
pub enum ZipError {
    #[error("ZIP inválido ou truncado: {0}")]
    Invalid(String),
}

#[derive(Clone, Debug)]
pub struct ZipEntryInput {
    pub name: String,
    pub data: Vec<u8>,
    pub store_uncompressed: bool,
    pub alignment: usize,
}

#[derive(Clone, Debug)]
pub struct ParsedZipEntry {
    pub name: String,
    pub method: u16,
    pub crc32: u32,
    pub compressed_size: u32,
    pub uncompressed_size: u32,
    pub local_header_offset: u32,
    pub data_offset: u32,
}

#[derive(Clone, Debug)]
pub struct BuiltZip {
    pub bytes: Vec<u8>,
    pub cd_offset: usize,
    pub cd_size: usize,
    pub entries: Vec<ParsedZipEntry>,
}

const EOCD_SIG: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];
const CD_SIG: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];
const LFH_SIG: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];

pub fn crc32_of(data: &[u8]) -> u32 {
    let mut h = Crc32::new();
    h.update(data);
    h.finalize()
}

pub fn build_zip(inputs: &[ZipEntryInput]) -> BuiltZip {
    let mut buf = Vec::new();
    let mut cd_records = Vec::new();
    let mut parsed_entries = Vec::new();

    for inp in inputs {
        let crc = crc32_of(&inp.data);
        let (method, compressed) = if inp.store_uncompressed {
            (0u16, inp.data.clone())
        } else {
            let mut enc = DeflateEncoder::new(Vec::new(), Compression::best());
            enc.write_all(&inp.data).expect("deflate write");
            let c = enc.finish().expect("deflate finish");
            if c.len() < inp.data.len() {
                (8u16, c)
            } else {
                (0u16, inp.data.clone())
            }
        };

        let name_bytes = inp.name.as_bytes();
        let lfh_offset = buf.len();

        // Para entradas stored alinhadas (resources.arsc=4B, lib*.so=4096B), ajusta extra field no LFH
        let align = inp.alignment.max(1);
        let pad_len = if method == 0 && align > 1 {
            let base_data_off = lfh_offset + 30 + name_bytes.len();
            let rem = base_data_off % align;
            if rem == 0 {
                0
            } else {
                // O próprio extra field tem 4 bytes de overhead apenas se não usarmos bytes crus;
                // no Android zipalign padrão usa-se padding zero direto no extra field!
                (align - rem) % align
            }
        } else {
            0
        };

        // Local File Header (30 bytes + filename + extra padding)
        buf.extend_from_slice(&LFH_SIG);
        buf.extend_from_slice(&20u16.to_le_bytes()); // version needed
        buf.extend_from_slice(&(1u16 << 11).to_le_bytes()); // UTF-8 bit 11
        buf.extend_from_slice(&method.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // mtime
        buf.extend_from_slice(&0x5421u16.to_le_bytes()); // mdate (fixed deterministic)
        buf.extend_from_slice(&crc.to_le_bytes());
        buf.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        buf.extend_from_slice(&(inp.data.len() as u32).to_le_bytes());
        buf.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(&(pad_len as u16).to_le_bytes());
        buf.extend_from_slice(name_bytes);
        if pad_len > 0 {
            buf.resize(buf.len() + pad_len, 0);
        }

        let data_offset = buf.len();
        buf.extend_from_slice(&compressed);

        // Central Directory File Header (46 bytes + filename)
        let mut cd = Vec::with_capacity(46 + name_bytes.len());
        cd.extend_from_slice(&CD_SIG);
        cd.extend_from_slice(&0x0314u16.to_le_bytes()); // version made by
        cd.extend_from_slice(&20u16.to_le_bytes()); // version needed
        cd.extend_from_slice(&(1u16 << 11).to_le_bytes());
        cd.extend_from_slice(&method.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0x5421u16.to_le_bytes());
        cd.extend_from_slice(&crc.to_le_bytes());
        cd.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        cd.extend_from_slice(&(inp.data.len() as u32).to_le_bytes());
        cd.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes()); // extra len
        cd.extend_from_slice(&0u16.to_le_bytes()); // comment len
        cd.extend_from_slice(&0u16.to_le_bytes()); // disk start
        cd.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        cd.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        cd.extend_from_slice(&(lfh_offset as u32).to_le_bytes());
        cd.extend_from_slice(name_bytes);
        cd_records.push(cd);

        parsed_entries.push(ParsedZipEntry {
            name: inp.name.clone(),
            method,
            crc32: crc,
            compressed_size: compressed.len() as u32,
            uncompressed_size: inp.data.len() as u32,
            local_header_offset: lfh_offset as u32,
            data_offset: data_offset as u32,
        });
    }

    let cd_offset = buf.len();
    for rec in &cd_records {
        buf.extend_from_slice(rec);
    }
    let cd_size = buf.len() - cd_offset;

    // End of Central Directory (22 bytes)
    buf.extend_from_slice(&EOCD_SIG);
    buf.extend_from_slice(&0u16.to_le_bytes()); // disk num
    buf.extend_from_slice(&0u16.to_le_bytes()); // cd start disk
    buf.extend_from_slice(&(inputs.len() as u16).to_le_bytes());
    buf.extend_from_slice(&(inputs.len() as u16).to_le_bytes());
    buf.extend_from_slice(&(cd_size as u32).to_le_bytes());
    buf.extend_from_slice(&(cd_offset as u32).to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes()); // comment len

    BuiltZip {
        bytes: buf,
        cd_offset,
        cd_size,
        entries: parsed_entries,
    }
}

pub fn find_eocd(apk: &[u8]) -> Result<usize, ZipError> {
    if apk.len() < 22 {
        return Err(ZipError::Invalid("arquivo menor que EOCD".into()));
    }
    let min_pos = apk.len().saturating_sub(65_557);
    for pos in (min_pos..=apk.len() - 22).rev() {
        if apk[pos..pos + 4] == EOCD_SIG {
            let comment_len = u16::from_le_bytes([apk[pos + 20], apk[pos + 21]]) as usize;
            if pos + 22 + comment_len == apk.len() {
                return Ok(pos);
            }
        }
    }
    Err(ZipError::Invalid("EOCD não encontrado".into()))
}

pub fn parse_central_directory(apk: &[u8]) -> Result<(usize, usize, usize, Vec<ParsedZipEntry>), ZipError> {
    let eocd = find_eocd(apk)?;
    let count = u16::from_le_bytes([apk[eocd + 10], apk[eocd + 11]]) as usize;
    let cd_size = u32::from_le_bytes(apk[eocd + 12..eocd + 16].try_into().unwrap()) as usize;
    let cd_offset = u32::from_le_bytes(apk[eocd + 16..eocd + 20].try_into().unwrap()) as usize;
    if cd_offset + cd_size > eocd {
        return Err(ZipError::Invalid("Central Directory fora dos limites".into()));
    }
    let mut pos = cd_offset;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        if pos + 46 > cd_offset + cd_size || apk[pos..pos + 4] != CD_SIG {
            return Err(ZipError::Invalid("entrada CD corrompida".into()));
        }
        let method = u16::from_le_bytes([apk[pos + 10], apk[pos + 11]]);
        let crc32 = u32::from_le_bytes(apk[pos + 16..pos + 20].try_into().unwrap());
        let csize = u32::from_le_bytes(apk[pos + 20..pos + 24].try_into().unwrap());
        let usize_val = u32::from_le_bytes(apk[pos + 24..pos + 28].try_into().unwrap());
        let nlen = u16::from_le_bytes([apk[pos + 28], apk[pos + 29]]) as usize;
        let elen = u16::from_le_bytes([apk[pos + 30], apk[pos + 31]]) as usize;
        let clen = u16::from_le_bytes([apk[pos + 32], apk[pos + 33]]) as usize;
        let lfh_off = u32::from_le_bytes(apk[pos + 42..pos + 46].try_into().unwrap());
        let name = String::from_utf8_lossy(&apk[pos + 46..pos + 46 + nlen]).to_string();
        let lfh_i = lfh_off as usize;
        if lfh_i + 30 > cd_offset || apk[lfh_i..lfh_i + 4] != LFH_SIG {
            return Err(ZipError::Invalid(format!("LFH inválido para {name}")));
        }
        let lfh_nlen = u16::from_le_bytes([apk[lfh_i + 26], apk[lfh_i + 27]]) as u32;
        let lfh_elen = u16::from_le_bytes([apk[lfh_i + 28], apk[lfh_i + 29]]) as u32;
        out.push(ParsedZipEntry {
            name,
            method,
            crc32,
            compressed_size: csize,
            uncompressed_size: usize_val,
            local_header_offset: lfh_off,
            data_offset: lfh_off + 30 + lfh_nlen + lfh_elen,
        });
        pos += 46 + nlen + elen + clen;
    }
    Ok((cd_offset, cd_size, eocd, out))
}

pub fn read_entry_data(apk: &[u8], e: &ParsedZipEntry) -> Result<Vec<u8>, ZipError> {
    let start = e.data_offset as usize;
    let end = start + e.compressed_size as usize;
    if end > apk.len() {
        return Err(ZipError::Invalid("dados da entrada truncados".into()));
    }
    let slice = &apk[start..end];
    let raw = match e.method {
        0 => slice.to_vec(),
        8 => {
            use flate2::read::DeflateDecoder;
            use std::io::Read;
            let mut dec = DeflateDecoder::new(slice);
            let mut out = Vec::new();
            dec.read_to_end(&mut out)
                .map_err(|err| ZipError::Invalid(format!("inflate falhou para {}: {err}", e.name)))?;
            out
        }
        other => return Err(ZipError::Invalid(format!("método ZIP não suportado: {other}"))),
    };
    if crc32_of(&raw) != e.crc32 || raw.len() != e.uncompressed_size as usize {
        return Err(ZipError::Invalid(format!("CRC/tamanho inválido para {}", e.name)));
    }
    Ok(raw)
}

pub fn inject_v2_signing_block(built: BuiltZip, signing_block: &[u8]) -> Vec<u8> {
    let pre_cd = &built.bytes[..built.cd_offset];
    let cd_bytes = &built.bytes[built.cd_offset..built.cd_offset + built.cd_size];
    let eocd_off = built.cd_offset + built.cd_size;
    let mut eocd = built.bytes[eocd_off..].to_vec();

    let new_cd_offset = (pre_cd.len() + signing_block.len()) as u32;
    eocd[16..20].copy_from_slice(&new_cd_offset.to_le_bytes());

    let mut out = Vec::with_capacity(pre_cd.len() + signing_block.len() + cd_bytes.len() + eocd.len());
    out.extend_from_slice(pre_cd);
    out.extend_from_slice(signing_block);
    out.extend_from_slice(cd_bytes);
    out.extend_from_slice(&eocd);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_entries_respect_4b_and_4096b_alignment() {
        let built = build_zip(&[
            ZipEntryInput {
                name: "resources.arsc".into(),
                data: vec![1, 2, 3, 4, 5],
                store_uncompressed: true,
                alignment: 4,
            },
            ZipEntryInput {
                name: "lib/arm64-v8a/libmycelium_daemon.so".into(),
                data: vec![0x7f, b'E', b'L', b'F', 2, 1, 1],
                store_uncompressed: true,
                alignment: 4096,
            },
        ]);
        let res = built.entries.iter().find(|e| e.name == "resources.arsc").unwrap();
        let so = built
            .entries
            .iter()
            .find(|e| e.name == "lib/arm64-v8a/libmycelium_daemon.so")
            .unwrap();
        assert_eq!(res.data_offset % 4, 0);
        assert_eq!(so.data_offset % 4096, 0);
        assert_eq!(res.method, 0);
        assert_eq!(so.method, 0);
        let (_, _, _, parsed) = parse_central_directory(&built.bytes).unwrap();
        assert_eq!(read_entry_data(&built.bytes, &parsed[1]).unwrap(), vec![0x7f, b'E', b'L', b'F', 2, 1, 1]);
    }
}
