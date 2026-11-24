use crate::apk_zip::{
    build_zip, inject_v2_signing_block, parse_central_directory, read_entry_data, ZipEntryInput,
    ZipError,
};
use crate::asn1::{
    build_pkcs7_detached, build_self_signed_cert, spki_p256_der, verify_pkcs7_detached,
    verifying_key_from_spki, Asn1Error,
};
use p256::ecdsa::{
    signature::{Signer, Verifier},
    DerSignature, SigningKey,
};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;

const APK_SIG_BLOCK_MAGIC: &[u8; 16] = b"APK Sig Block 42";
const APK_SIG_SCHEME_V2_ID: u32 = 0x7109_871a;
const SIG_ALG_ECDSA_SHA256: u32 = 0x0201;

#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    #[error("ZIP inválido: {0}")]
    Zip(#[from] ZipError),
    #[error("ASN.1 / PKCS#7 inválido: {0}")]
    Asn1(#[from] Asn1Error),
    #[error("chave inválida: {0}")]
    Key(String),
    #[error("assinatura APK v1 inválida: {0}")]
    V1Invalid(String),
    #[error("assinatura APK v2 inválida: {0}")]
    V2Invalid(String),
    #[error("alinhamento APK inválido: {0}")]
    Alignment(String),
    #[error("IO: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Clone, Debug)]
pub struct VerificationReport {
    pub v1_manifest_entries: usize,
    pub v2_chunk_digest_hex: String,
    pub spki_sha256_hex: String,
    pub arsc_data_offset: u32,
    pub native_lib_data_offset: u32,
}

fn b64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[(n >> 18) & 0x3f] as char);
        out.push(TABLE[(n >> 12) & 0x3f] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) & 0x3f] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n & 0x3f] as char
        } else {
            '='
        });
    }
    out
}

pub fn load_or_create_signing_key(key_path: Option<&Path>) -> Result<SigningKey, SignerError> {
    if let Some(p) = key_path {
        if p.exists() {
            let txt = std::fs::read_to_string(p)?;
            let raw = hex::decode(txt.trim())
                .map_err(|e| SignerError::Key(format!("hex inválido em {}: {e}", p.display())))?;
            return SigningKey::from_slice(&raw)
                .map_err(|e| SignerError::Key(format!("P-256 inválido em {}: {e}", p.display())));
        }
        if let Some(parent) = p.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let sk = SigningKey::random(&mut OsRng);
        std::fs::write(p, format!("{}\n", hex::encode(sk.to_bytes())))?;
        return Ok(sk);
    }
    Ok(SigningKey::random(&mut OsRng))
}

fn len_prefixed_u32(inner: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + inner.len());
    out.extend_from_slice(&(inner.len() as u32).to_le_bytes());
    out.extend_from_slice(inner);
    out
}

fn compute_v2_chunk_merkle_root(s1: &[u8], s2: &[u8], s3: &[u8]) -> [u8; 32] {
    const CHUNK: usize = 1024 * 1024;
    let mut chunk_digests = Vec::<[u8; 32]>::new();
    for section in [s1, s2, s3] {
        for part in section.chunks(CHUNK) {
            let mut h = Sha256::new();
            h.update([0xa5u8]);
            h.update((part.len() as u32).to_le_bytes());
            h.update(part);
            chunk_digests.push(h.finalize().into());
        }
    }
    let mut top = Sha256::new();
    top.update([0x5au8]);
    top.update((chunk_digests.len() as u32).to_le_bytes());
    for cd in &chunk_digests {
        top.update(cd);
    }
    top.finalize().into()
}

pub fn build_and_sign_apk(
    base_entries: &[ZipEntryInput],
    sk: &SigningKey,
) -> Result<Vec<u8>, SignerError> {
    let serial = 1u64;
    let cn = "Mycelium Rhizome Sovereign";
    let org = "Mycelium Lattice";
    let (cert_der, spki_der) = build_self_signed_cert(sk, serial, cn, org);
    debug_assert_eq!(spki_der, spki_p256_der(sk.verifying_key()));

    // 1. V1 JAR Signatures (MANIFEST.MF, CERT.SF, CERT.EC)
    let mut manifest_mf = String::from(
        "Manifest-Version: 1.0\r\nCreated-By: mycelium-android-forge\r\n\r\n",
    );
    let mut sf_sections = Vec::<(String, String)>::new();
    for entry in base_entries {
        if entry.name.starts_with("META-INF/") {
            continue;
        }
        let d_b64 = b64_encode(&Sha256::digest(&entry.data));
        let section = format!(
            "Name: {}\r\nSHA-256-Digest: {}\r\n\r\n",
            entry.name, d_b64
        );
        manifest_mf.push_str(&section);
        let sec_digest_b64 = b64_encode(&Sha256::digest(section.as_bytes()));
        sf_sections.push((entry.name.clone(), sec_digest_b64));
    }
    let manifest_bytes = manifest_mf.into_bytes();
    let mf_full_digest_b64 = b64_encode(&Sha256::digest(&manifest_bytes));

    let mut cert_sf = format!(
        "Signature-Version: 1.0\r\nCreated-By: mycelium-android-forge\r\nSHA-256-Digest-Manifest: {}\r\n\r\n",
        mf_full_digest_b64
    );
    for (name, sec_d) in sf_sections {
        cert_sf.push_str(&format!("Name: {}\r\nSHA-256-Digest: {}\r\n\r\n", name, sec_d));
    }
    let cert_sf_bytes = cert_sf.into_bytes();
    let cert_ec_bytes = build_pkcs7_detached(&cert_der, serial, cn, org, sk, &cert_sf_bytes);

    let mut all_entries = Vec::with_capacity(base_entries.len() + 3);
    all_entries.extend_from_slice(base_entries);
    all_entries.push(ZipEntryInput {
        name: "META-INF/MANIFEST.MF".into(),
        data: manifest_bytes,
        store_uncompressed: false,
        alignment: 1,
    });
    all_entries.push(ZipEntryInput {
        name: "META-INF/CERT.SF".into(),
        data: cert_sf_bytes,
        store_uncompressed: false,
        alignment: 1,
    });
    all_entries.push(ZipEntryInput {
        name: "META-INF/CERT.EC".into(),
        data: cert_ec_bytes,
        store_uncompressed: false,
        alignment: 1,
    });

    let built = build_zip(&all_entries);

    // 2. APK Signature Scheme v2 (antes do Central Directory, preservando offsets de dados!)
    let pre_cd = &built.bytes[..built.cd_offset];
    let cd = &built.bytes[built.cd_offset..built.cd_offset + built.cd_size];
    let eocd = &built.bytes[built.cd_offset + built.cd_size..];

    let root_digest = compute_v2_chunk_merkle_root(pre_cd, cd, eocd);

    // digests_seq = lp([lp([u32 alg_id, lp(root_digest)])])
    let mut digest_entry = Vec::new();
    digest_entry.extend_from_slice(&SIG_ALG_ECDSA_SHA256.to_le_bytes());
    digest_entry.extend_from_slice(&len_prefixed_u32(&root_digest));
    let digests_seq = len_prefixed_u32(&len_prefixed_u32(&digest_entry));

    // certs_seq = lp([lp(cert_der)])
    let certs_seq = len_prefixed_u32(&len_prefixed_u32(&cert_der));
    // additional_attrs = empty
    let add_attrs = 0u32.to_le_bytes();

    let mut signed_data = Vec::new();
    signed_data.extend_from_slice(&digests_seq);
    signed_data.extend_from_slice(&certs_seq);
    signed_data.extend_from_slice(&add_attrs);

    let v2_sig: DerSignature = sk.sign(&signed_data);
    let mut sig_entry = Vec::new();
    sig_entry.extend_from_slice(&SIG_ALG_ECDSA_SHA256.to_le_bytes());
    sig_entry.extend_from_slice(&len_prefixed_u32(v2_sig.as_bytes()));
    let sigs_seq = len_prefixed_u32(&len_prefixed_u32(&sig_entry));

    let mut signer = Vec::new();
    signer.extend_from_slice(&len_prefixed_u32(&signed_data));
    signer.extend_from_slice(&sigs_seq);
    signer.extend_from_slice(&len_prefixed_u32(&spki_der));

    let v2_value = len_prefixed_u32(&len_prefixed_u32(&signer));

    // Pair inside APK Signing Block
    let pair_len = (4 + v2_value.len()) as u64;
    let block_size_of_block = (8 + pair_len as usize + 8 + 16) as u64;

    let mut block = Vec::with_capacity(block_size_of_block as usize + 8);
    block.extend_from_slice(&block_size_of_block.to_le_bytes());
    block.extend_from_slice(&pair_len.to_le_bytes());
    block.extend_from_slice(&APK_SIG_SCHEME_V2_ID.to_le_bytes());
    block.extend_from_slice(&v2_value);
    block.extend_from_slice(&block_size_of_block.to_le_bytes());
    block.extend_from_slice(APK_SIG_BLOCK_MAGIC);

    Ok(inject_v2_signing_block(built, &block))
}

fn read_u32_le(s: &[u8]) -> Result<(u32, &[u8]), SignerError> {
    if s.len() < 4 {
        return Err(SignerError::V2Invalid("EOF lendo u32".into()));
    }
    Ok((u32::from_le_bytes(s[..4].try_into().unwrap()), &s[4..]))
}

fn read_lp(s: &[u8]) -> Result<(&[u8], &[u8]), SignerError> {
    let (len, rest) = read_u32_le(s)?;
    let l = len as usize;
    if l > rest.len() {
        return Err(SignerError::V2Invalid("prefixo de comprimento excede bloco v2".into()));
    }
    Ok((&rest[..l], &rest[l..]))
}

/// Verifica independentemente assinaturas v1 (MANIFEST.MF + CERT.SF + CERT.EC),
/// assinatura APK v2 (`0x7109871a` Merkle root + ECDSA) e alinhamento ZIP de `resources.arsc` e `.so`.
pub fn verify_apk(apk: &[u8]) -> Result<VerificationReport, SignerError> {
    let (cd_offset, cd_size, eocd_off, entries) = parse_central_directory(apk)?;

    // 1. Valida alinhamentos ZIP críticos
    let arsc = entries
        .iter()
        .find(|e| e.name == "resources.arsc")
        .ok_or_else(|| SignerError::Alignment("resources.arsc ausente".into()))?;
    if arsc.method != 0 || arsc.data_offset % 4 != 0 {
        return Err(SignerError::Alignment(
            "resources.arsc precisa ser stored com offset múltiplo de 4 bytes".into(),
        ));
    }
    let so = entries
        .iter()
        .find(|e| e.name == "lib/arm64-v8a/libmycelium_daemon.so")
        .ok_or_else(|| SignerError::Alignment("libmycelium_daemon.so ausente".into()))?;
    if so.method != 0 || so.data_offset % 4096 != 0 {
        return Err(SignerError::Alignment(
            "libmycelium_daemon.so precisa ser stored com offset múltiplo de 4096 bytes".into(),
        ));
    }

    // 2. Verifica todos os hashes SHA-256 no v1 JAR (MANIFEST.MF + CERT.SF + CERT.EC)
    let find_entry = |n: &str| {
        entries
            .iter()
            .find(|e| e.name == n)
            .ok_or_else(|| SignerError::V1Invalid(format!("entrada v1 ausente: {n}")))
    };
    let mf_bytes = read_entry_data(apk, find_entry("META-INF/MANIFEST.MF")?)?;
    let sf_bytes = read_entry_data(apk, find_entry("META-INF/CERT.SF")?)?;
    let ec_bytes = read_entry_data(apk, find_entry("META-INF/CERT.EC")?)?;

    let v1_spki = verify_pkcs7_detached(&ec_bytes, &sf_bytes)?;

    let sf_str = std::str::from_utf8(&sf_bytes)
        .map_err(|_| SignerError::V1Invalid("CERT.SF não UTF-8".into()))?;
    let expected_mf_b64 = b64_encode(&Sha256::digest(&mf_bytes));
    let mut sf_sections = sf_str.split("\r\n\r\n");
    let sf_main = sf_sections
        .next()
        .ok_or_else(|| SignerError::V1Invalid("cabeçalho CERT.SF ausente".into()))?;
    if !sf_main.contains(&format!("SHA-256-Digest-Manifest: {expected_mf_b64}")) {
        return Err(SignerError::V1Invalid(
            "SHA-256-Digest-Manifest em CERT.SF não confere com MANIFEST.MF".into(),
        ));
    }

    let mut sf_digests = HashMap::new();
    for sec in sf_sections.filter(|s| !s.trim().is_empty()) {
        let mut name = None;
        let mut dig = None;
        for line in sec.split("\r\n") {
            if let Some(v) = line.strip_prefix("Name: ") {
                name = Some(v.to_string());
            } else if let Some(v) = line.strip_prefix("SHA-256-Digest: ") {
                dig = Some(v.to_string());
            }
        }
        if let (Some(n), Some(d)) = (name, dig) {
            sf_digests.insert(n, d);
        }
    }

    let mf_str = std::str::from_utf8(&mf_bytes)
        .map_err(|_| SignerError::V1Invalid("MANIFEST.MF não UTF-8".into()))?;
    let mut mf_count = 0usize;
    let mut seen_names = HashMap::new();
    for raw_sec in mf_str.split("\r\n\r\n").skip(1).filter(|s| !s.trim().is_empty()) {
        let full_sec = format!("{raw_sec}\r\n\r\n");
        let mut name = None;
        let mut dig = None;
        for line in raw_sec.split("\r\n") {
            if let Some(v) = line.strip_prefix("Name: ") {
                name = Some(v.to_string());
            } else if let Some(v) = line.strip_prefix("SHA-256-Digest: ") {
                dig = Some(v.to_string());
            }
        }
        let n = name.ok_or_else(|| SignerError::V1Invalid("seção MANIFEST sem Name".into()))?;
        let d = dig.ok_or_else(|| SignerError::V1Invalid("seção MANIFEST sem SHA-256".into()))?;
        let sec_hash = b64_encode(&Sha256::digest(full_sec.as_bytes()));
        if sf_digests.get(&n) != Some(&sec_hash) {
            return Err(SignerError::V1Invalid(format!(
                "digest de seção SF inválido para {n}"
            )));
        }
        let ent = find_entry(&n)?;
        let content = read_entry_data(apk, ent)?;
        if b64_encode(&Sha256::digest(&content)) != d {
            return Err(SignerError::V1Invalid(format!(
                "SHA-256 do conteúdo não confere para {n}"
            )));
        }
        seen_names.insert(n, true);
        mf_count += 1;
    }
    for e in &entries {
        if !e.name.starts_with("META-INF/") && !seen_names.contains_key(&e.name) {
            return Err(SignerError::V1Invalid(format!(
                "entrada não listada no manifesto v1: {}",
                e.name
            )));
        }
    }

    // 3. Verifica APK Signature Scheme v2 (`APK Sig Block 42` imediatamente antes do CD)
    if cd_offset < 32 || &apk[cd_offset - 16..cd_offset] != APK_SIG_BLOCK_MAGIC {
        return Err(SignerError::V2Invalid("APK Sig Block 42 ausente".into()));
    }
    let footer_size =
        u64::from_le_bytes(apk[cd_offset - 24..cd_offset - 16].try_into().unwrap()) as usize;
    let block_total = footer_size + 8;
    if block_total > cd_offset {
        return Err(SignerError::V2Invalid("tamanho inválido do bloco v2".into()));
    }
    let block_start = cd_offset - block_total;
    let header_size = u64::from_le_bytes(apk[block_start..block_start + 8].try_into().unwrap()) as usize;
    if header_size != footer_size {
        return Err(SignerError::V2Invalid("tamanhos de cabeçalho/rodapé do bloco v2 diferem".into()));
    }

    let mut pairs = &apk[block_start + 8..cd_offset - 24];
    let mut v2_val_opt = None;
    while !pairs.is_empty() {
        if pairs.len() < 12 {
            return Err(SignerError::V2Invalid("par do bloco v2 truncado".into()));
        }
        let plen = u64::from_le_bytes(pairs[..8].try_into().unwrap()) as usize;
        if 8 + plen > pairs.len() || plen < 4 {
            return Err(SignerError::V2Invalid("tamanho de par v2 inválido".into()));
        }
        let pid = u32::from_le_bytes(pairs[8..12].try_into().unwrap());
        let pval = &pairs[12..8 + plen];
        if pid == APK_SIG_SCHEME_V2_ID {
            v2_val_opt = Some(pval);
        }
        pairs = &pairs[8 + plen..];
    }
    let v2_val = v2_val_opt.ok_or_else(|| SignerError::V2Invalid("par ID 0x7109871a ausente".into()))?;

    let (signers_seq, _) = read_lp(v2_val)?;
    let (signer_bytes, _) = read_lp(signers_seq)?;
    let (signed_data_bytes, rem) = read_lp(signer_bytes)?;
    let (sigs_seq, rem) = read_lp(rem)?;
    let (spki_bytes, _) = read_lp(rem)?;
    if spki_bytes != v1_spki.as_slice() {
        return Err(SignerError::V2Invalid("chave pública v2 difere do certificado v1".into()));
    }

    let (digests_seq, _) = read_lp(signed_data_bytes)?;
    let (dig_entry, _) = read_lp(digests_seq)?;
    let (dig_alg, rem_dig) = read_u32_le(dig_entry)?;
    if dig_alg != SIG_ALG_ECDSA_SHA256 {
        return Err(SignerError::V2Invalid("algoritmo v2 inesperado".into()));
    }
    let (claimed_digest, _) = read_lp(rem_dig)?;

    let (sig_entry, _) = read_lp(sigs_seq)?;
    let (sig_alg, rem_sig) = read_u32_le(sig_entry)?;
    if sig_alg != SIG_ALG_ECDSA_SHA256 {
        return Err(SignerError::V2Invalid("algoritmo de assinatura v2 inesperado".into()));
    }
    let (sig_der_bytes, _) = read_lp(rem_sig)?;

    let vk = verifying_key_from_spki(spki_bytes)?;
    let sig = DerSignature::from_bytes(sig_der_bytes)
        .map_err(|e| SignerError::V2Invalid(format!("ECDSA DER inválido: {e}")))?;
    vk.verify(signed_data_bytes, &sig)
        .map_err(|e| SignerError::V2Invalid(format!("assinatura ECDSA v2 rejeitada: {e}")))?;

    // Recomuta Merkle root 1 MiB sobre pre_block + cd + eocd (com offset CD ajustado para block_start)
    let mut eocd_for_digest = apk[eocd_off..].to_vec();
    eocd_for_digest[16..20].copy_from_slice(&(block_start as u32).to_le_bytes());
    let actual_root = compute_v2_chunk_merkle_root(
        &apk[..block_start],
        &apk[cd_offset..cd_offset + cd_size],
        &eocd_for_digest,
    );
    if actual_root.as_slice() != claimed_digest {
        return Err(SignerError::V2Invalid(
            "Merkle root SHA-256 v2 não confere com conteúdo/CD/EoCD".into(),
        ));
    }

    Ok(VerificationReport {
        v1_manifest_entries: mf_count,
        v2_chunk_digest_hex: hex::encode(actual_root),
        spki_sha256_hex: hex::encode(Sha256::digest(spki_bytes)),
        arsc_data_offset: arsc.data_offset,
        native_lib_data_offset: so.data_offset,
    })
}
