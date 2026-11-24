use mycelium_pay::cbor::{self, Value};
use mycelium_pay::envelope::{Envelope, Sig, Type};

const SK: [u8; 32] = [0x11; 32];

fn body() -> Value {
    Value::Map(vec![(1, Value::Bytes(vec![0xab; 16])), (0, Value::Uint(1000)), (2, Value::Array(vec![Value::Uint(300), Value::Uint(70000)]))])
}

#[test]
fn cbor_canonical_roundtrip_sorts_keys() {
    let enc = cbor::encode(&body()).unwrap();
    assert_eq!(enc[0], 0xa3); // map(3)
    assert_eq!(enc[1], 0x00); // chave 0 primeiro, mesmo declarada por último
    let Value::Map(m) = cbor::decode(&enc).unwrap() else { panic!() };
    assert_eq!(m.iter().map(|(k, _)| *k).collect::<Vec<_>>(), [0, 1, 2]);
    assert_eq!(cbor::encode(&cbor::decode(&enc).unwrap()).unwrap(), enc);
}

#[test]
fn cbor_rejects_non_canonical() {
    for (name, bytes) in [
        ("uint não-mínimo", vec![0x18, 0x05]),
        ("uint16 que cabe em 1 byte", vec![0x19, 0x00, 0xff]),
        ("mapa fora de ordem", vec![0xa2, 0x01, 0x00, 0x00, 0x00]),
        ("chave duplicada", vec![0xa2, 0x00, 0x00, 0x00, 0x01]),
        ("sobra", vec![0x00, 0x00]),
        ("array indefinido", vec![0x9f, 0xff]),
        ("texto não-UTF-8", vec![0x61, 0xff]),
        ("texto não-mínimo", vec![0x78, 0x01, 0x61]),
        ("negativo", vec![0x20]),
        ("tag", vec![0xc1, 0x00]),
        ("float", vec![0xf9, 0x00, 0x00]),
        ("truncado", vec![0x58, 0x05, 0x00]),
        ("array gigante", vec![0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
        ("chave não-inteira", vec![0xa1, 0x41, 0x00, 0x00]),
    ] {
        assert!(cbor::decode(&bytes).is_err(), "deveria rejeitar: {name}");
    }
    assert!(cbor::encode(&Value::Map(vec![(1, Value::Uint(0)), (1, Value::Uint(0))])).is_err());
}

#[test]
fn envelope_sign_encode_decode_verify() {
    let mut e = Envelope::new(Type::PayRequest, &body()).unwrap();
    e.sign_bip340(&SK).unwrap();
    let wire = e.encode().unwrap();
    let d = Envelope::decode(&wire).unwrap();
    assert_eq!(d, e);
    d.verify().unwrap();
    assert_eq!(d.id(), *blake3::hash(&d.body).as_bytes());
}

#[test]
fn envelope_rejects_bad_inputs() {
    let mut e = Envelope::new(Type::Receipt, &body()).unwrap();
    assert!(e.verify().is_err(), "sem assinatura");
    e.sign_bip340(&SK).unwrap();

    let mut t = e.clone();
    t.body[0] ^= 1; // corpo adulterado
    assert!(t.verify().is_err());

    let mut t = e.clone();
    t.ty = Type::TokenSend; // domínio do tipo faz parte do que se assina
    assert!(t.verify().is_err());

    let mut t = e.clone();
    t.sigs.push(Sig { alg: 99, pubkey: vec![], sig: vec![] }); // alg desconhecido: falha fechada
    assert!(t.verify().is_err());

    let mut wire = e.encode().unwrap();
    wire[2] = 0x02; // versão 2
    assert!(Envelope::decode(&wire).is_err());
    assert!(Envelope::decode(&[]).is_err());
}

/// Vetor: envelope assinado, bytes exatos. Outra implementação deve reproduzi-los.
#[test]
fn envelope_v1_vector() {
    let mut e = Envelope::new(Type::PayRequest, &body()).unwrap();
    e.sign_bip340(&SK).unwrap();
    assert_eq!(hex::encode(&e.body), "a3001903e80150abababababababababababababababab028219012c1a00011170");
    assert_eq!(hex::encode(e.id()), "bb313133af0a9fab73dcc881d22be57aa16a5da090610c8659475a632ccf8859");
    assert_eq!(hex::encode(e.msg()), "50145195cc0b4ade6c8f0e3d19032e9cecdb4d861d62fc32ff0459e898a4b779");
    assert_eq!(hex::encode(e.encode().unwrap()), "a400010101025821a3001903e80150abababababababababababababababab028219012c1a000111700381a300010158204f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa025840897cec2e0a7cd17eb5ef1a8465247d6ee9eec85b86e1a5e905ebbc0399289415d3d31dcf98ac3f1b75f6e654bfc345b206ffd38b5b7351b7a57430857ae8e8e0");
}
