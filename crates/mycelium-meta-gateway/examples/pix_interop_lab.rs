mod api {
    pub use mycelium_meta_gateway::bse_web_pix::{inspect_pix, PixKind};
    pub use mycelium_meta_gateway::{
        bse_web_http as http_observer, bse_web_iso as iso20022, bse_web_pix_json as pix_json,
        bse_web_pix_state as pix_state, bse_web_psp_lab as psp_lab,
    };
}
// W9: deterministic synthetic differential corpus; no network or financial effects.
use api::http_observer::{observe_http_trace, BodyState};
use api::iso20022::{compare_decoded_charge, inspect_iso, Comparison};
use api::pix_json::{inspect_json, Context, PayloadKind};
use api::pix_state::{replay_json, validate_retry_days, RetryPolicy, State};
use api::psp_lab::run_lab;
use serde_json::json;
const STATIC:&str="00020126580014br.gov.bcb.pix0136123e4567-e12b-12d1-a456-4266554400005204000053039865802BR5913Fulano de Tal6008BRASILIA62070503***63041D3D";
const DYNAMIC:&str="00020101021226700014br.gov.bcb.pix2548pix.example.com/8b3da2f39a4140d1a91abd93113bd4415204000053039865802BR5913Fulano de Tal6008BRASILIA62070503***630464E4";
const REC:&str="00020126180014br.gov.bcb.pix5204000053039865802BR5913Fulano de Tal6008BRASILIA62070503***80740014br.gov.bcb.pix2552pix.example.com/rec/2353c790eefb11eaadc10242ac1200026304F2DA";
fn cob() -> serde_json::Value {
    json!({"revisao":0,"calendario":{"criacao":"2026-11-25T10:00:00Z","apresentacao":"2026-11-25T10:01:00Z"},"valor":{"original":"12.34"},"chave":"fixture@example.invalid","txid":"ABCDEFGHIJKLMNOPQRSTUVWXYZ","status":"ATIVA"})
}
fn trace(path: &str, status: u16, ct: &str, body: &str) -> String {
    json!({"method":"GET","path":path,"status":status,"content_type":ct,"body":body}).to_string()
}
fn record<T: std::fmt::Debug + PartialEq>(case: &str, actual: T, expected: T) {
    assert_eq!(actual, expected, "oracle mismatch in {case}");
    println!("{case}\t{actual:?}");
}
fn main() {
    use api::PixKind::*;
    for (name, fixture, kind, payment, rec) in [
        ("static", STATIC, Static, true, false),
        ("dynamic", DYNAMIC, Dynamic, true, false),
        ("rec", REC, Compound, false, true),
    ] {
        let x = api::inspect_pix(fixture).unwrap();
        record(
            &format!("w1/{name}"),
            (x.kind, x.has_payment, x.has_recurrence, x.amount_cents),
            (kind, payment, rec, None),
        );
        // Every proper prefix is structurally incomplete (CRC required).
        for i in 0..fixture.len() {
            record(
                &format!("w1/{name}/prefix/{i}"),
                api::inspect_pix(&fixture[..i]).is_err(),
                true,
            );
        }
        // Single ASCII substitution in data, retaining the original CRC.
        for i in 0..fixture.len() - 4 {
            let mut m = fixture.as_bytes().to_vec();
            m[i] = if m[i] == b'X' { b'Y' } else { b'X' };
            record(
                &format!("w1/{name}/mutate/{i}"),
                api::inspect_pix(std::str::from_utf8(&m).unwrap()).is_err(),
                true,
            );
        }
    }
    let base = cob();
    for (name, v, expected) in [
        ("fixed", base.clone(), Some(1234)),
        ("editable", base.clone(), None),
    ] {
        let mut v = v;
        if name == "editable" {
            v = base.clone();
            v["valor"] = json!({"original":"0.00","modalidadeAlteracao":1});
        }
        let s = v.to_string();
        let x = inspect_json(&s, PayloadKind::Cob, Context::Dynamic).unwrap();
        record(
            &format!("w2/{name}"),
            (x.final_cents, x.is_verified()),
            (expected, false),
        );
        let y =
            observe_http_trace(&trace("/lab/payload/cob", 200, "application/json", &s)).unwrap();
        record(
            &format!("w3/{name}"),
            (y.body_state, y.declared_status.as_deref(), y.is_verified()),
            (BodyState::DecodedJson, Some("ATIVA"), false),
        );
    }
    for (name, val) in [
        ("number", json!(12.34)),
        ("negative", json!("-1.00")),
        ("precision", json!("1.234")),
        ("zero", json!("0.00")),
        ("null", json!(null)),
    ] {
        let mut v = base.clone();
        v["valor"]["original"] = val;
        let s = v.to_string();
        record(
            &format!("w2/{name}"),
            inspect_json(&s, PayloadKind::Cob, Context::Dynamic).is_err(),
            true,
        );
        record(
            &format!("w3/{name}"),
            observe_http_trace(&trace("/lab/payload/cob", 200, "application/json", &s))
                .unwrap()
                .body_state,
            BodyState::InvalidJson,
        );
    }
    let duplicate = base.to_string().replace(
        "\"original\":\"12.34\"",
        "\"original\":\"12.34\",\"original\":\"12.35\"",
    );
    record(
        "w2/duplicate",
        inspect_json(&duplicate, PayloadKind::Cob, Context::Dynamic).is_err(),
        true,
    );
    record(
        "w3/duplicate",
        observe_http_trace(&trace(
            "/lab/payload/cob",
            200,
            "application/json",
            &duplicate,
        ))
        .unwrap()
        .body_state,
        BodyState::InvalidJson,
    );
    for (code, expected) in [
        (200, BodyState::DecodedJson),
        (201, BodyState::NotInspected),
        (302, BodyState::NotInspected),
        (401, BodyState::NotInspected),
        (503, BodyState::NotInspected),
    ] {
        record(
            &format!("w3/status/{code}"),
            observe_http_trace(&trace(
                "/lab/payload/cob",
                code,
                "application/json",
                &base.to_string(),
            ))
            .unwrap()
            .body_state,
            expected,
        );
    }
    record(
        "w3/jose",
        observe_http_trace(&trace(
            "/lab/payload/cob",
            200,
            "application/jose",
            "fixture",
        ))
        .unwrap()
        .body_state,
        BodyState::SignedEnvelopeNotVerified,
    );
    record(
        "w3/wrong-resource",
        observe_http_trace(&trace(
            "/lab/payload/cobv",
            200,
            "application/json",
            &base.to_string(),
        ))
        .unwrap()
        .body_state,
        BodyState::InvalidJson,
    );
    record(
        "w3/outside-lab",
        observe_http_trace(&trace(
            "https://example.invalid",
            200,
            "application/json",
            "{}",
        ))
        .is_err(),
        true,
    );
    // Only inspect synthetic partial XML; never serialize an order for dispatch.
    let xml = |reference: &str, amount: &str| {
        format!(
            r#"<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.008.001.01"><FIToFICstmrCdtTrf><CdtTrfTxInf><PmtId><TxId>{reference}</TxId></PmtId><IntrBkSttlmAmt Ccy="BRL">{amount}</IntrBkSttlmAmt></CdtTrfTxInf></FIToFICstmrCdtTrf></Document>"#
        )
    };
    for (name, r, a, ref_result, amount_result) in [
        (
            "match",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "12.34",
            Comparison::Match,
            Comparison::Match,
        ),
        (
            "amount-mismatch",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "12.35",
            Comparison::Match,
            Comparison::Mismatch,
        ),
        (
            "reference-mismatch",
            "different",
            "12.34",
            Comparison::Mismatch,
            Comparison::Match,
        ),
    ] {
        let x = compare_decoded_charge(&xml(r, a), &base.to_string(), PayloadKind::Cob).unwrap();
        record(
            &format!("w2-w5/{name}"),
            (x.reference, x.amount, x.is_verified()),
            (ref_result, amount_result, false),
        );
    }
    let mut due = base.clone();
    due["calendario"]["dataDeVencimento"] = json!("2026-12-01");
    due["calendario"]["validadeAposVencimento"] = json!(30);
    due["devedor"] = json!({"nome":"DEMO"});
    due["recebedor"] =
        json!({"nome":"DEMO","logradouro":"TESTE","cidade":"TESTE","uf":"CE","cep":"00000000"});
    due["valor"] = json!({"original":"12.34","desconto":"1.00","juros":"0.50","final":"11.84"});
    let x = compare_decoded_charge(
        &xml("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "11.84"),
        &due.to_string(),
        PayloadKind::Cobv,
    )
    .unwrap();
    record(
        "w2-w5/due-final",
        (x.reference, x.amount),
        (Comparison::Match, Comparison::Match),
    );
    let x = compare_decoded_charge(
        &xml("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "12.34"),
        &due.to_string(),
        PayloadKind::Cobv,
    )
    .unwrap();
    record("w2-w5/due-original", x.amount, Comparison::Mismatch);
    record(
        "w5/dtd",
        inspect_iso("<!DOCTYPE x [<!ENTITY a 'x'>]><x/>").is_err(),
        true,
    );
    record(
        "w5/wrong-currency",
        inspect_iso(&xml("fixture", "12.34").replace("BRL", "USD")).is_err(),
        true,
    );
    let valid =
        r#"{"entity":"solic_rec","steps":[{"to":"ENVIADA"},{"to":"RECEBIDA"},{"to":"ACEITA"}]}"#;
    let invalid = r#"{"entity":"solic_rec","steps":[{"to":"ACEITA"}]}"#;
    let x = replay_json(valid).unwrap();
    record(
        "w4/valid",
        (x.final_state, x.steps, x.is_verified()),
        (State::Aceita, 3, false),
    );
    record("w4/invalid", replay_json(invalid).is_err(), true);
    for (name, days, allowed) in [
        ("empty", vec![], true),
        ("max", vec![1, 3, 7], true),
        ("repeat", vec![1, 1], false),
        ("late", vec![8], false),
        ("many", vec![1, 2, 3, 4], false),
    ] {
        record(
            &format!("w4/retry/{name}"),
            validate_retry_days(RetryPolicy::Permite3r7d, &days).is_ok(),
            allowed,
        );
    }
    let x = run_lab().unwrap();
    record(
        "w6/flags",
        [
            x.directory_ok,
            x.idempotency_ok,
            x.simulated_transfer_ok,
            x.insufficient_credits_rejected,
            x.duplicate_prevented,
            x.cancel_ok,
            x.conserved,
            x.w1_fixture_ok,
            x.w2_fixture_ok,
            x.w3_fixture_ok,
            x.w5_fixture_ok,
        ],
        [true; 11],
    );
    record(
        "w6/credits",
        (x.buyer_credits, x.merchant_credits, x.is_verified()),
        (880, 120, false),
    );
}
