use mycelium_pay::bodies::*;
use mycelium_pay::cbor::Value;
use mycelium_pay::envelope::{Envelope, Type};

fn req() -> PayRequest {
    PayRequest {
        payment_id: [1; 16],
        single_use: true,
        amount: 2100,
        unit: "sat".into(),
        mints: vec!["https://mint.example".into()],
        p2pk: [2; 32],
        expires_at: 1_900_000_000,
        transports: vec!["nostr:wss://relay.example".into(), "hyphae".into()],
    }
}

#[test]
fn all_bodies_roundtrip_through_signed_envelope() {
    let r = req();
    let mut e = r.envelope().unwrap();
    e.sign_bip340(&[7; 32]).unwrap();
    let d = Envelope::decode(&e.encode().unwrap()).unwrap();
    d.verify().unwrap();
    assert_eq!(PayRequest::from_envelope(&d).unwrap(), r);

    let t = TokenSend { payment_id: [1; 16], token: "cashuBabc".into() };
    assert_eq!(TokenSend::from_envelope(&t.envelope().unwrap()).unwrap(), t);
    let rc = Receipt { payment_id: [1; 16], token_send_id: [3; 32], status: Status::Redeemed, code: 0, ts: 5 };
    assert_eq!(Receipt::from_envelope(&rc.envelope().unwrap()).unwrap(), rc);
    let l = LnInvoice { payment_id: [1; 16], bolt11: "lnbc1...".into() };
    assert_eq!(LnInvoice::from_envelope(&l.envelope().unwrap()).unwrap(), l);
}

#[test]
fn wrong_type_extra_missing_or_bad_fields_rejected() {
    let e = req().envelope().unwrap();
    assert!(TokenSend::from_envelope(&e).is_err(), "tipo errado");

    let Value::Map(mut m) = req().to_value() else { panic!() };
    let mut extra = m.clone();
    extra.push((8, Value::Uint(0)));
    assert!(PayRequest::from_value(Value::Map(extra)).is_err(), "campo extra");
    m.pop();
    assert!(PayRequest::from_value(Value::Map(m.clone())).is_err(), "campo faltando");

    let mut full = req().to_value();
    if let Value::Map(f) = &mut full {
        f[1].1 = Value::Uint(2);
    }
    assert!(PayRequest::from_value(full).is_err(), "single_use=2");

    let mut short = req().to_value();
    if let Value::Map(f) = &mut short {
        f[0].1 = Value::Bytes(vec![0; 15]);
    }
    assert!(PayRequest::from_value(short).is_err(), "payment_id curto");
}

#[test]
fn receipt_status_code_consistency() {
    let mk = |status, code| Receipt { payment_id: [0; 16], token_send_id: [0; 32], status, code, ts: 0 };
    for (s, c, ok) in [
        (Status::Received, 0, true),
        (Status::Redeemed, 0, true),
        (Status::Error, 1, true),
        (Status::Error, 8, true),
        (Status::Error, 0, false),
        (Status::Redeemed, 3, false),
        (Status::Error, 9, false),
    ] {
        assert_eq!(Receipt::from_envelope(&mk(s, c).envelope().unwrap()).is_ok(), ok, "{s:?} {c}");
    }
    assert_eq!(Type::Receipt as u8, 3);
}
