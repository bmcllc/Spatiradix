//! KAT oficial NIST ACVP (FIPS 204 KeyGen, ML-DSA-87) para `mldsa_signing_key_from_seed`.
#![cfg(feature = "license")]
use mycelium_zkp::license::{mldsa_signing_key_from_seed, Keypair};

#[test]
fn mldsa87_keygen_nist_acvp() {
    std::thread::Builder::new()
        .stack_size(32 << 20)
        .spawn(|| {
            let v: serde_json::Value = serde_json::from_str(include_str!("vectors/mldsa87_keygen.json")).unwrap();
            for t in v["tests"].as_array().unwrap() {
                let h = |k: &str| hex::decode(t[k].as_str().unwrap()).unwrap();
                let xi: [u8; 32] = h("seed").try_into().unwrap();
                let pk = mldsa_signing_key_from_seed(&xi).verifying_key().encode().as_slice().to_vec();
                assert_eq!(pk, h("pk"));
            }
        })
        .unwrap()
        .join()
        .unwrap();
}
