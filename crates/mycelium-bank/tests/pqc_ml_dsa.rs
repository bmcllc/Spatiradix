#![cfg(feature = "pqc-ml-dsa")]

use mycelium_bank::pqc::ml_dsa::MlDsaKey;

#[test]
fn ml_dsa_sign_verify() {
    let key = MlDsaKey::generate();
    let msg = b"pagamento sovereign";
    let sig = key.sign(msg);
    assert!(MlDsaKey::verify(&key.public_key_bytes(), msg, &sig));
    assert!(!MlDsaKey::verify(&key.public_key_bytes(), b"alterado", &sig));
}

#[test]
fn ml_dsa_seed_deterministic() {
    let seed = [7u8; 32];
    let a = MlDsaKey::from_seed(seed);
    let b = MlDsaKey::from_seed(seed);
    let msg = b"x";
    let sa = a.sign(msg);
    let sb = b.sign(msg);
    assert_eq!(sa, sb);
}
