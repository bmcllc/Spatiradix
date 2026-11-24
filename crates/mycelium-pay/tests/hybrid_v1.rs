use mycelium_pay::hybrid::{open, seal, Recipient, RecipientSecret};
use mycelium_pay::PayError;
use secp256k1::{SecretKey, SECP256K1};

const R_SK: [u8; 32] = [0x22; 32];
const S_SK: [u8; 32] = [0x33; 32];
const MSG: &[u8] = b"envelope-bytes-go-here";

fn xonly(sk: &[u8; 32]) -> [u8; 32] {
    SecretKey::from_byte_array(*sk).unwrap().public_key(SECP256K1).x_only_public_key().0.serialize()
}

fn pq_pair() -> (Recipient, RecipientSecret) {
    let kp = mycelium_pqc::mlkem_keygen_from_seed(&[5u8; 64]);
    (
        Recipient { xonly: xonly(&R_SK), mlkem_pub: Some(kp.public_key.clone()) },
        RecipientSecret { secret: R_SK, mlkem_dk: Some(kp.private_bytes().to_vec()) },
    )
}

fn classic_pair() -> (Recipient, RecipientSecret) {
    (Recipient { xonly: xonly(&R_SK), mlkem_pub: None }, RecipientSecret { secret: R_SK, mlkem_dk: None })
}

#[test]
fn pq_roundtrip() {
    let (to, me) = pq_pair();
    let wire = seal(&to, &S_SK, MSG).unwrap();
    assert_eq!(wire[..2], [1, 1]);
    assert_eq!(open(&me, &wire, true).unwrap(), MSG);
}

#[test]
fn classic_nip44_roundtrip() {
    let (to, me) = classic_pair();
    let wire = seal(&to, &S_SK, MSG).unwrap();
    assert_eq!(wire[..2], [1, 0]);
    assert_eq!(open(&me, &wire, false).unwrap(), MSG);
}

#[test]
fn hybrid_downgrade_rejected() {
    // remetente malicioso força flag 0 contra quem anunciou ML-KEM
    let (_, me) = pq_pair();
    let (classic_to, _) = classic_pair();
    let wire = seal(&classic_to, &S_SK, MSG).unwrap();
    assert!(matches!(open(&me, &wire, true), Err(PayError::Downgrade)));
    // contato que anunciou PQ antes, mesmo que a chave local não tenha dk
    let (_, no_dk) = classic_pair();
    assert!(matches!(open(&no_dk, &wire, true), Err(PayError::Downgrade)));
}

#[test]
fn pq_tamper_is_rejected_everywhere() {
    let (to, me) = pq_pair();
    let wire = seal(&to, &S_SK, MSG).unwrap();
    for i in [2, 40, 1000, wire.len() - 1] {
        // E, ct (início e meio), tag do AEAD
        let mut t = wire.clone();
        t[i] ^= 1;
        assert!(open(&me, &t, true).is_err(), "byte {i} adulterado foi aceito");
    }
    let mut t = wire.clone();
    t[0] = 2;
    assert!(open(&me, &t, true).is_err());
    assert!(open(&me, &wire[..20], true).is_err());
    let other = RecipientSecret { secret: [0x44; 32], mlkem_dk: me.mlkem_dk.clone() };
    assert!(open(&other, &wire, true).is_err(), "outra chave secp256k1");
}

/// Vetor fixo: chaves derivadas das seeds `[5;64]` (ML-KEM) e `R_SK`; o decifrador de qualquer
/// implementação deve recuperar `MSG`. O ciphertext é fixo porque a encapsulação é aleatória.
#[test]
fn hybrid_kem_vector() {
    let (_, me) = pq_pair();
    let wire = hex::decode(include_str!("vectors/hybrid_v1.hex").trim()).unwrap();
    assert_eq!(open(&me, &wire, true).unwrap(), MSG);
}
