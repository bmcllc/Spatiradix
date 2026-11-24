//! Cifra híbrida (§7.3). `pq_flag=1`: secp256k1-ECDH + ML-KEM-1024 → ChaCha20-Poly1305.
//! `pq_flag=0`: caminho separado, NIP-44 v2 puro. Anti-downgrade: quem anunciou ML-KEM só aceita flag 1.
//!
//! Fio flag=1: `v ‖ 1 ‖ E(32) ‖ ct(1568) ‖ aead`. Fio flag=0: `v ‖ 0 ‖ remetente(32) ‖ base64(nip44)`.

use crate::PayError;
use base64::Engine;
use chacha20poly1305::{aead::Aead, aead::Payload, ChaCha20Poly1305, KeyInit};
use rand::RngCore;
use secp256k1::{ecdh, Parity, PublicKey, SecretKey, XOnlyPublicKey, SECP256K1};

const V: u8 = 1;
const CT_LEN: usize = 1568; // ML-KEM-1024

pub struct Recipient {
    pub xonly: [u8; 32],
    /// Presente ⇒ o destinatário anunciou ML-KEM e o envio DEVE ser `pq_flag=1`.
    pub mlkem_pub: Option<Vec<u8>>,
}

pub struct RecipientSecret {
    pub secret: [u8; 32],
    pub mlkem_dk: Option<Vec<u8>>,
}

fn sk(b: &[u8; 32]) -> Result<SecretKey, PayError> {
    SecretKey::from_byte_array(*b).map_err(|_| PayError::Hybrid("chave secp256k1 inválida"))
}

fn xonly(b: &[u8; 32]) -> Result<XOnlyPublicKey, PayError> {
    XOnlyPublicKey::from_byte_array(*b).map_err(|_| PayError::Hybrid("chave x-only inválida"))
}

/// `x(ECDH(secret, X))`; a paridade de `X` não altera a coordenada x.
fn ecdh_x(secret: &SecretKey, x: &XOnlyPublicKey) -> [u8; 32] {
    let pt = ecdh::shared_secret_point(&PublicKey::from_x_only_public_key(*x, Parity::Even), secret);
    pt[..32].try_into().unwrap()
}

fn transcript(e: &[u8], x_r: &[u8; 32], ct: &[u8], pk_hash: &[u8; 32]) -> Vec<u8> {
    [b"mycelium/v1/hybrid".as_slice(), &[V], e, x_r, ct, pk_hash, &[1]].concat()
}

fn aead_key(ss1: &[u8; 32], ss2: &[u8], t: &[u8]) -> [u8; 32] {
    let material = [ss1.as_slice(), ss2, blake3::hash(t).as_bytes()].concat();
    blake3::derive_key("mycelium/v1/hybrid/key", &material)
}

/// `sender_secret` só é usado no caminho flag=0 (NIP-44 usa chave estática do remetente).
pub fn seal(to: &Recipient, sender_secret: &[u8; 32], envelope: &[u8]) -> Result<Vec<u8>, PayError> {
    match &to.mlkem_pub {
        Some(pk_r) => {
            let mut eb = [0u8; 32];
            let e = loop {
                rand::rngs::OsRng.fill_bytes(&mut eb);
                if let Ok(e) = SecretKey::from_byte_array(eb) {
                    break e;
                }
            };
            let e_x = e.public_key(SECP256K1).x_only_public_key().0.serialize();
            let ss1 = ecdh_x(&e, &xonly(&to.xonly)?);
            let enc = mycelium_pqc::mlkem_encapsulate(pk_r).map_err(|_| PayError::Hybrid("encapsulate"))?;
            let pk_hash = *blake3::hash(pk_r).as_bytes();
            let t = transcript(&e_x, &to.xonly, &enc.ciphertext, &pk_hash);
            let key = aead_key(&ss1, &enc.shared_secret, &t);
            let ct = ChaCha20Poly1305::new(&key.into())
                .encrypt(&[0u8; 12].into(), Payload { msg: envelope, aad: &t })
                .map_err(|_| PayError::Hybrid("aead"))?;
            Ok([&[V, 1][..], &e_x, &enc.ciphertext, &ct].concat())
        }
        None => {
            let s = sk(sender_secret)?;
            let convo = nip44::get_conversation_key(s, xonly(&to.xonly)?);
            let text = base64::engine::general_purpose::STANDARD.encode(envelope);
            let payload = nip44::encrypt(&convo, &text).map_err(|_| PayError::Hybrid("nip44"))?;
            let me = s.public_key(SECP256K1).x_only_public_key().0.serialize();
            Ok([&[V, 0][..], &me, payload.as_bytes()].concat())
        }
    }
}

/// `pq_required`: o contato já anunciou ML-KEM (descritor/PayRequest) ⇒ flag 0 é recusado.
pub fn open(me: &RecipientSecret, wire: &[u8], pq_required: bool) -> Result<Vec<u8>, PayError> {
    let [v, flag, rest @ ..] = wire else { return Err(PayError::Hybrid("curto")) };
    if *v != V {
        return Err(PayError::Hybrid("versão"));
    }
    let s = sk(&me.secret)?;
    match flag {
        0 => {
            if pq_required || me.mlkem_dk.is_some() {
                return Err(PayError::Downgrade);
            }
            let (sender, payload) = rest.split_at_checked(32).ok_or(PayError::Hybrid("curto"))?;
            let convo = nip44::get_conversation_key(s, xonly(sender.try_into().unwrap())?);
            let text = nip44::decrypt(&convo, std::str::from_utf8(payload).map_err(|_| PayError::Hybrid("utf8"))?)
                .map_err(|_| PayError::Hybrid("nip44"))?;
            base64::engine::general_purpose::STANDARD.decode(text).map_err(|_| PayError::Hybrid("base64"))
        }
        1 => {
            let dk = me.mlkem_dk.as_ref().ok_or(PayError::Hybrid("sem chave ML-KEM"))?;
            let (e_x, rest) = rest.split_at_checked(32).ok_or(PayError::Hybrid("curto"))?;
            let (ct, aead) = rest.split_at_checked(CT_LEN).ok_or(PayError::Hybrid("curto"))?;
            let ss1 = ecdh_x(&s, &xonly(e_x.try_into().unwrap())?);
            let ss2 = mycelium_pqc::mlkem_decapsulate(dk, ct).map_err(|_| PayError::Hybrid("decapsulate"))?;
            let kp = mycelium_pqc::mlkem_keypair_from_private(dk).map_err(|_| PayError::Hybrid("dk"))?;
            let pk = &kp.public_key;
            let x_r = s.public_key(SECP256K1).x_only_public_key().0.serialize();
            let t = transcript(e_x, &x_r, ct, blake3::hash(pk).as_bytes());
            let key = aead_key(&ss1, &ss2, &t);
            ChaCha20Poly1305::new(&key.into())
                .decrypt(&[0u8; 12].into(), Payload { msg: aead, aad: &t })
                .map_err(|_| PayError::Hybrid("aead: autenticação falhou"))
        }
        _ => Err(PayError::Hybrid("pq_flag")),
    }
}
