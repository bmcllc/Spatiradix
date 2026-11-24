use p256::ecdsa::{
    signature::{Signer, Verifier},
    DerSignature, SigningKey, VerifyingKey,
};
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum Asn1Error {
    #[error("DER truncado ou malformado: {0}")]
    Malformed(String),
    #[error("assinatura ECDSA P-256 inválida: {0}")]
    BadSignature(String),
    #[error("digest SHA-256 não confere com atributo messageDigest")]
    DigestMismatch,
}

pub fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
    out.push(tag);
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xff {
        out.push(0x81);
        out.push(len as u8);
    } else if len <= 0xffff {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xff) as u8);
    } else if len <= 0xff_ffff {
        out.push(0x83);
        out.push((len >> 16) as u8);
        out.push(((len >> 8) & 0xff) as u8);
        out.push((len & 0xff) as u8);
    } else {
        out.push(0x84);
        out.extend_from_slice(&(len as u32).to_be_bytes());
    }
    out.extend_from_slice(content);
    out
}

pub fn der_sequence(items: &[&[u8]]) -> Vec<u8> {
    let body: Vec<u8> = items.iter().flat_map(|s| s.iter().copied()).collect();
    der_tlv(0x30, &body)
}

pub fn der_set_sorted(items: &[&[u8]]) -> Vec<u8> {
    let mut sorted: Vec<&[u8]> = items.to_vec();
    sorted.sort();
    let body: Vec<u8> = sorted.iter().flat_map(|s| s.iter().copied()).collect();
    der_tlv(0x31, &body)
}

pub fn der_integer_big(bytes: &[u8]) -> Vec<u8> {
    let mut trimmed = bytes;
    while trimmed.len() > 1 && trimmed[0] == 0 {
        trimmed = &trimmed[1..];
    }
    if trimmed.is_empty() {
        return der_tlv(0x02, &[0]);
    }
    if trimmed[0] & 0x80 != 0 {
        let mut buf = Vec::with_capacity(trimmed.len() + 1);
        buf.push(0x00);
        buf.extend_from_slice(trimmed);
        der_tlv(0x02, &buf)
    } else {
        der_tlv(0x02, trimmed)
    }
}

pub fn der_integer_u64(v: u64) -> Vec<u8> {
    der_integer_big(&v.to_be_bytes())
}

pub fn der_bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(bytes.len() + 1);
    buf.push(0x00);
    buf.extend_from_slice(bytes);
    der_tlv(0x03, &buf)
}

pub fn der_octet_string(bytes: &[u8]) -> Vec<u8> {
    der_tlv(0x04, bytes)
}

pub fn der_null() -> Vec<u8> {
    vec![0x05, 0x00]
}

pub fn der_boolean(v: bool) -> Vec<u8> {
    der_tlv(0x01, &[if v { 0xff } else { 0x00 }])
}

pub fn der_oid(arcs: &[u32]) -> Vec<u8> {
    assert!(arcs.len() >= 2);
    let mut body = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for &arc in &arcs[2..] {
        let mut stack = [0u8; 5];
        let mut n = 0;
        let mut val = arc;
        loop {
            stack[n] = (val & 0x7f) as u8;
            n += 1;
            val >>= 7;
            if val == 0 {
                break;
            }
        }
        for i in (0..n).rev() {
            let b = if i > 0 { stack[i] | 0x80 } else { stack[i] };
            body.push(b);
        }
    }
    der_tlv(0x06, &body)
}

pub fn der_utf8(s: &str) -> Vec<u8> {
    der_tlv(0x0c, s.as_bytes())
}

pub fn der_utc_time(s: &str) -> Vec<u8> {
    der_tlv(0x17, s.as_bytes())
}

pub fn der_explicit(tag_no: u8, inner: &[u8]) -> Vec<u8> {
    der_tlv(0xa0 | (tag_no & 0x1f), inner)
}

pub fn der_implicit_constructed(tag_no: u8, inner_bytes: &[u8]) -> Vec<u8> {
    der_tlv(0xa0 | (tag_no & 0x1f), inner_bytes)
}

pub fn spki_p256_der(vk: &VerifyingKey) -> Vec<u8> {
    let oid_ec = der_oid(&[1, 2, 840, 10045, 2, 1]);
    let oid_p256 = der_oid(&[1, 2, 840, 10045, 3, 1, 7]);
    let alg = der_sequence(&[&oid_ec, &oid_p256]);
    let point = vk.to_encoded_point(false);
    let bits = der_bit_string(point.as_bytes());
    der_sequence(&[&alg, &bits])
}

pub fn build_self_signed_cert(
    sk: &SigningKey,
    serial: u64,
    cn: &str,
    org: &str,
) -> (Vec<u8>, Vec<u8>) {
    let vk = sk.verifying_key();
    let spki = spki_p256_der(vk);
    let version = der_explicit(0, &der_integer_u64(2)); // v3
    let serial_der = der_integer_u64(serial.max(1));
    let oid_ecdsa_sha256 = der_oid(&[1, 2, 840, 10045, 4, 3, 2]);
    let sig_alg = der_sequence(&[&oid_ecdsa_sha256]);

    let rdn_org = der_set_sorted(&[&der_sequence(&[&der_oid(&[2, 5, 4, 10]), &der_utf8(org)])]);
    let rdn_cn = der_set_sorted(&[&der_sequence(&[&der_oid(&[2, 5, 4, 3]), &der_utf8(cn)])]);
    let name = der_sequence(&[&rdn_org, &rdn_cn]);
    let validity = der_sequence(&[
        &der_utc_time("260101000000Z"),
        &der_utc_time("491231235959Z"),
    ]);

    // BasicConstraints(CA:FALSE), KeyUsage(digitalSignature = bit 0 -> 0x80 with 7 unused bits)
    let bc_ext = der_sequence(&[
        &der_oid(&[2, 5, 29, 19]),
        &der_boolean(true),
        &der_octet_string(&der_sequence(&[])),
    ]);
    let ku_bits = der_tlv(0x03, &[0x07, 0x80]);
    let ku_ext = der_sequence(&[
        &der_oid(&[2, 5, 29, 15]),
        &der_boolean(true),
        &der_octet_string(&ku_bits),
    ]);
    let exts = der_explicit(3, &der_sequence(&[&bc_ext, &ku_ext]));

    let tbs = der_sequence(&[
        &version,
        &serial_der,
        &sig_alg,
        &name,
        &validity,
        &name,
        &spki,
        &exts,
    ]);
    let sig: DerSignature = sk.sign(&tbs);
    let cert = der_sequence(&[&tbs, &sig_alg, &der_bit_string(sig.as_bytes())]);
    (cert, spki)
}

pub fn build_pkcs7_detached(
    cert_der: &[u8],
    serial: u64,
    cn: &str,
    org: &str,
    sk: &SigningKey,
    content: &[u8],
) -> Vec<u8> {
    let oid_sha256 = der_oid(&[2, 16, 840, 1, 101, 3, 4, 2, 1]);
    let sha256_alg = der_sequence(&[&oid_sha256, &der_null()]);
    let digest_algs = der_set_sorted(&[&sha256_alg]);

    let oid_data = der_oid(&[1, 2, 840, 113549, 1, 7, 1]);
    let encap = der_sequence(&[&oid_data]);

    let certs_choice = der_implicit_constructed(0, cert_der);

    let rdn_org = der_set_sorted(&[&der_sequence(&[&der_oid(&[2, 5, 4, 10]), &der_utf8(org)])]);
    let rdn_cn = der_set_sorted(&[&der_sequence(&[&der_oid(&[2, 5, 4, 3]), &der_utf8(cn)])]);
    let issuer = der_sequence(&[&rdn_org, &rdn_cn]);
    let sid = der_sequence(&[&issuer, &der_integer_u64(serial.max(1))]);

    let content_digest = Sha256::digest(content);
    let attr_ct = der_sequence(&[
        &der_oid(&[1, 2, 840, 113549, 1, 9, 3]),
        &der_set_sorted(&[&oid_data]),
    ]);
    let attr_time = der_sequence(&[
        &der_oid(&[1, 2, 840, 113549, 1, 9, 5]),
        &der_set_sorted(&[&der_utc_time("260101000000Z")]),
    ]);
    let attr_digest = der_sequence(&[
        &der_oid(&[1, 2, 840, 113549, 1, 9, 4]),
        &der_set_sorted(&[&der_octet_string(&content_digest)]),
    ]);

    let mut attrs_list = vec![attr_ct.as_slice(), attr_time.as_slice(), attr_digest.as_slice()];
    attrs_list.sort();
    let attrs_body: Vec<u8> = attrs_list.into_iter().flat_map(|s| s.iter().copied()).collect();
    let attrs_set_der = der_tlv(0x31, &attrs_body);
    let attrs_implicit_der = der_tlv(0xa0, &attrs_body);

    let sig: DerSignature = sk.sign(&attrs_set_der);
    let sig_alg = der_sequence(&[&der_oid(&[1, 2, 840, 10045, 4, 3, 2])]);

    let signer_info = der_sequence(&[
        &der_integer_u64(1),
        &sid,
        &sha256_alg,
        &attrs_implicit_der,
        &sig_alg,
        &der_octet_string(sig.as_bytes()),
    ]);
    let signer_infos = der_set_sorted(&[&signer_info]);

    let signed_data = der_sequence(&[
        &der_integer_u64(1),
        &digest_algs,
        &encap,
        &certs_choice,
        &signer_infos,
    ]);
    let oid_signed_data = der_oid(&[1, 2, 840, 113549, 1, 7, 2]);
    der_sequence(&[&oid_signed_data, &der_explicit(0, &signed_data)])
}

/// Leitor DER mínimo para verificar independentemente Certificado X.509 e CMS/PKCS#7.
struct DerNode<'a> {
    tag: u8,
    raw: &'a [u8],
    value: &'a [u8],
}

fn parse_one_der(input: &[u8]) -> Result<(DerNode<'_>, &[u8]), Asn1Error> {
    if input.len() < 2 {
        return Err(Asn1Error::Malformed("EOF inesperado no DER".into()));
    }
    let tag = input[0];
    let len_byte = input[1];
    let (hdr_len, val_len) = if len_byte < 0x80 {
        (2usize, len_byte as usize)
    } else {
        let count = (len_byte & 0x7f) as usize;
        if count == 0 || count > 4 || input.len() < 2 + count {
            return Err(Asn1Error::Malformed("comprimento DER inválido".into()));
        }
        let mut l = 0usize;
        for b in &input[2..2 + count] {
            l = (l << 8) | (*b as usize);
        }
        (2 + count, l)
    };
    let end = hdr_len
        .checked_add(val_len)
        .ok_or_else(|| Asn1Error::Malformed("overflow de comprimento DER".into()))?;
    if end > input.len() {
        return Err(Asn1Error::Malformed("bloco DER excede buffer".into()));
    }
    Ok((
        DerNode {
            tag,
            raw: &input[..end],
            value: &input[hdr_len..end],
        },
        &input[end..],
    ))
}

fn parse_der_children(mut body: &[u8]) -> Result<Vec<DerNode<'_>>, Asn1Error> {
    let mut items = Vec::new();
    while !body.is_empty() {
        let (node, rest) = parse_one_der(body)?;
        items.push(node);
        body = rest;
    }
    Ok(items)
}

pub fn verifying_key_from_spki(spki_der: &[u8]) -> Result<VerifyingKey, Asn1Error> {
    let (seq, rest) = parse_one_der(spki_der)?;
    if seq.tag != 0x30 || !rest.is_empty() {
        return Err(Asn1Error::Malformed("SPKI não é SEQUENCE".into()));
    }
    let children = parse_der_children(seq.value)?;
    if children.len() != 2 || children[1].tag != 0x03 || children[1].value.is_empty() {
        return Err(Asn1Error::Malformed("SPKI BIT STRING ausente".into()));
    }
    let point_bytes = &children[1].value[1..];
    VerifyingKey::from_sec1_bytes(point_bytes)
        .map_err(|e| Asn1Error::BadSignature(format!("chave P-256 inválida no SPKI: {e}")))
}

pub fn verify_pkcs7_detached(pkcs7_der: &[u8], content: &[u8]) -> Result<Vec<u8>, Asn1Error> {
    let (ci, rest) = parse_one_der(pkcs7_der)?;
    if ci.tag != 0x30 || !rest.is_empty() {
        return Err(Asn1Error::Malformed("PKCS7 raiz inválido".into()));
    }
    let ci_children = parse_der_children(ci.value)?;
    if ci_children.len() < 2 || ci_children[1].tag != 0xa0 {
        return Err(Asn1Error::Malformed("ContentInfo SignedData ausente".into()));
    }
    let (sd, _) = parse_one_der(ci_children[1].value)?;
    let sd_children = parse_der_children(sd.value)?;
    let certs_node = sd_children
        .iter()
        .find(|n| n.tag == 0xa0)
        .ok_or_else(|| Asn1Error::Malformed("certificado ausente no SignedData".into()))?;
    let (cert_node, _) = parse_one_der(certs_node.value)?;
    let cert_parts = parse_der_children(cert_node.value)?;
    if cert_parts.len() < 3 {
        return Err(Asn1Error::Malformed("X.509 malformado".into()));
    }
    let tbs = cert_parts[0].raw;
    let tbs_fields = parse_der_children(cert_parts[0].value)?;
    let spki_node = tbs_fields
        .iter()
        .filter(|n| n.tag == 0x30)
        .nth(4) // sigAlg(0), issuer(1), validity(2), subject(3), spki(4)
        .ok_or_else(|| Asn1Error::Malformed("SPKI ausente no certificado".into()))?;
    let vk = verifying_key_from_spki(spki_node.raw)?;

    // Verifica auto-assinatura do certificado X.509
    let cert_sig_bits = &cert_parts[2].value[1..];
    let cert_sig = DerSignature::from_bytes(cert_sig_bits)
        .map_err(|e| Asn1Error::BadSignature(format!("assinatura cert: {e}")))?;
    vk.verify(tbs, &cert_sig)
        .map_err(|e| Asn1Error::BadSignature(format!("cert self-sig: {e}")))?;

    // SignerInfos SET OF
    let signer_infos_node = sd_children
        .last()
        .ok_or_else(|| Asn1Error::Malformed("SignerInfos ausente".into()))?;
    let signer_infos = parse_der_children(signer_infos_node.value)?;
    let si = signer_infos
        .first()
        .ok_or_else(|| Asn1Error::Malformed("SignerInfo vazio".into()))?;
    let si_fields = parse_der_children(si.value)?;
    let signed_attrs = si_fields
        .iter()
        .find(|n| n.tag == 0xa0)
        .ok_or_else(|| Asn1Error::Malformed("signedAttrs ausente".into()))?;

    // Verifica atributo messageDigest == SHA256(content)
    let expected_digest = Sha256::digest(content);
    let md_oid = der_oid(&[1, 2, 840, 113549, 1, 9, 4]);
    let mut found_digest = false;
    for attr in parse_der_children(signed_attrs.value)? {
        let parts = parse_der_children(attr.value)?;
        if parts.len() == 2 && parts[0].raw == md_oid.as_slice() {
            let set_items = parse_der_children(parts[1].value)?;
            if let Some(oct) = set_items.first() {
                if oct.value == expected_digest.as_slice() {
                    found_digest = true;
                }
            }
        }
    }
    if !found_digest {
        return Err(Asn1Error::DigestMismatch);
    }

    // Reconstroi SET DER (0x31) para validar assinatura do SignerInfo
    let attrs_set_der = der_tlv(0x31, signed_attrs.value);
    let sig_octet = si_fields
        .last()
        .ok_or_else(|| Asn1Error::Malformed("signature octet string ausente".into()))?;
    let si_sig = DerSignature::from_bytes(sig_octet.value)
        .map_err(|e| Asn1Error::BadSignature(format!("assinatura SignerInfo: {e}")))?;
    vk.verify(&attrs_set_der, &si_sig)
        .map_err(|e| Asn1Error::BadSignature(format!("verificação SignerInfo: {e}")))?;

    Ok(spki_node.raw.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn cert_and_pkcs7_roundtrip() {
        let sk = SigningKey::random(&mut OsRng);
        let (cert, spki) = build_self_signed_cert(&sk, 1, "Mycelium Test", "Lattice");
        let sf = b"Signature-Version: 1.0\r\nSHA-256-Digest-Manifest: abcd\r\n\r\n";
        let p7 = build_pkcs7_detached(&cert, 1, "Mycelium Test", "Lattice", &sk, sf);
        let verified_spki = verify_pkcs7_detached(&p7, sf).expect("PKCS7 válido");
        assert_eq!(verified_spki, spki);
        assert!(verify_pkcs7_detached(&p7, b"tampered").is_err());
    }
}
