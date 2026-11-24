//! KAT oficial NIST ACVP (FIPS 203 KeyGen) para `mlkem_keygen_from_seed`.
use mycelium_pqc::mlkem_keygen_from_seed;

#[test]
fn mlkem1024_keygen_nist_acvp() {
    let v: serde_json::Value = serde_json::from_str(include_str!("vectors/mlkem1024_keygen.json")).unwrap();
    let tests = v["tests"].as_array().unwrap();
    assert!(!tests.is_empty());
    for t in tests {
        let h = |k: &str| hex::decode(t[k].as_str().unwrap()).unwrap();
        let seed: [u8; 64] = [h("d"), h("z")].concat().try_into().unwrap();
        let kp = mlkem_keygen_from_seed(&seed);
        assert_eq!(kp.public_key, h("ek"));
        assert_eq!(kp.private_bytes(), h("dk"));
    }
}
