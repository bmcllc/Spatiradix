//! W2: inspect decoded Pix JSON, not a JWS verifier or a payment executor.
//! Manual v2.10.0 sections 2.7.1, 2.8.4, annex IV.
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadKind {
    Cob,
    Cobv,
    Rec,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Context {
    Dynamic,
    Compound,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticPayload {
    pub kind: PayloadKind,
    pub reference: String,
    pub declared_status: String,
    pub revision: Option<u64>,
    pub original_cents: Option<u64>,
    pub final_cents: Option<u64>,
    pub editable_amount: bool,
    pub expiry_seconds: Option<u64>,
    pub recurrence_minimum_cents: Option<u64>,
    pub recurrence_periodicity: Option<String>,
}
impl SemanticPayload {
    /// Inspection alone can never establish authenticity, consent or settlement.
    pub const fn is_verified(&self) -> bool {
        false
    }
}
type R<T> = Result<T, &'static str>;
type Obj = Map<String, Value>;

// Reject duplicate keys recursively rather than allowing last-value-wins.
struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Unique;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("JSON without duplicate keys")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Unique, E> {
                Ok(Unique(Value::Bool(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_none<E: de::Error>(self) -> Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Unique, A::Error> {
                let mut v = Vec::new();
                while let Some(x) = a.next_element::<Unique>()? {
                    v.push(x.0);
                }
                Ok(Unique(Value::Array(v)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Unique, A::Error> {
                let mut m = Map::new();
                while let Some((k, v)) = a.next_entry::<String, Unique>()? {
                    if m.insert(k, v.0).is_some() {
                        return Err(de::Error::custom("duplicate key"));
                    }
                }
                Ok(Unique(Value::Object(m)))
            }
        }
        d.deserialize_any(V)
    }
}
fn obj<'a>(o: &'a Obj, k: &str) -> R<&'a Obj> {
    o.get(k)
        .and_then(Value::as_object)
        .ok_or("required object absent or invalid")
}
fn opt_obj<'a>(o: &'a Obj, k: &str) -> R<Option<&'a Obj>> {
    o.get(k)
        .map(|v| v.as_object().ok_or("invalid optional object"))
        .transpose()
}
fn string<'a>(o: &'a Obj, k: &str) -> R<&'a str> {
    o.get(k)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty() && !s.chars().any(char::is_control))
        .ok_or("required string absent or invalid")
}
fn opt_string<'a>(o: &'a Obj, k: &str) -> R<Option<&'a str>> {
    o.get(k).map(|_| string(o, k)).transpose()
}
fn integer(o: &Obj, k: &str) -> R<u64> {
    o.get(k)
        .and_then(Value::as_u64)
        .filter(|n| *n <= i32::MAX as u64)
        .ok_or("invalid nonnegative integer")
}
fn opt_int(o: &Obj, k: &str) -> R<Option<u64>> {
    o.get(k).map(|_| integer(o, k)).transpose()
}
fn digits(s: &str, n: usize) -> bool {
    s.len() == n && s.bytes().all(|b| b.is_ascii_digit())
}
fn date(s: &str) -> bool {
    if !s.is_ascii()
        || s.len() != 10
        || &s[4..5] != "-"
        || &s[7..8] != "-"
        || !digits(&s[..4], 4)
        || !digits(&s[5..7], 2)
        || !digits(&s[8..], 2)
    {
        return false;
    }
    let y: u32 = s[..4].parse().unwrap();
    let m: u32 = s[5..7].parse().unwrap();
    let d: u32 = s[8..].parse().unwrap();
    let max = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) => 29,
        2 => 28,
        _ => 0,
    };
    y > 0 && d > 0 && d <= max
}
fn timestamp(s: &str) -> bool {
    if !s.is_ascii()
        || s.len() < 20
        || !date(&s[..10])
        || &s[10..11] != "T"
        || &s[13..14] != ":"
        || &s[16..17] != ":"
    {
        return false;
    }
    for (p, max) in [(11, 23), (14, 59), (17, 59)] {
        if !digits(&s[p..p + 2], 2) || s[p..p + 2].parse::<u8>().unwrap() > max {
            return false;
        }
    }
    let suffix = &s[19..];
    let Some(t) = suffix
        .strip_suffix('Z')
        .or_else(|| suffix.strip_suffix("+00:00"))
    else {
        return false;
    };
    t.is_empty()
        || t.strip_prefix('.')
            .is_some_and(|f| !f.is_empty() && f.bytes().all(|b| b.is_ascii_digit()))
}
fn date_field<'a>(o: &'a Obj, k: &str) -> R<&'a str> {
    let s = string(o, k)?;
    if !date(s) {
        return Err("invalid ISO date");
    }
    Ok(s)
}
fn ts(o: &Obj, k: &str) -> R<()> {
    if !timestamp(string(o, k)?) {
        return Err("invalid UTC timestamp");
    }
    Ok(())
}
fn money(s: &str) -> R<u64> {
    let (a, b) = s.split_once('.').ok_or("invalid monetary format")?;
    if a.is_empty() || a.len() > 10 || !a.bytes().all(|x| x.is_ascii_digit()) || !digits(b, 2) {
        return Err("invalid monetary format");
    }
    Ok(a.parse::<u64>().unwrap() * 100 + b.parse::<u64>().unwrap())
}
fn opt_money(o: &Obj, k: &str) -> R<Option<u64>> {
    opt_string(o, k)?.map(money).transpose()
}
fn cnpj(s: &str) -> bool {
    s.len() == 14
        && s.is_ascii()
        && s[..12]
            .bytes()
            .all(|b| b.is_ascii_digit() || b.is_ascii_uppercase())
        && digits(&s[12..], 2)
}
fn party(o: &Obj, required_name: bool) -> R<()> {
    let cpf = opt_string(o, "cpf")?;
    let cnpj_s = opt_string(o, "cnpj")?;
    if cpf.is_some() && cnpj_s.is_some()
        || cpf.is_some_and(|s| !digits(s, 11))
        || cnpj_s.is_some_and(|s| !cnpj(s))
    {
        return Err("invalid party identifier");
    }
    if required_name || cpf.is_some() || cnpj_s.is_some() {
        string(o, "nome")?;
    } else {
        opt_string(o, "nome")?;
    }
    Ok(())
}
fn charge_status(s: &str) -> bool {
    matches!(
        s,
        "ATIVA"
            | "CONCLUIDA"
            | "CONCLUÍDA"
            | "REMOVIDO_PELO_USUARIO_RECEBEDOR"
            | "REMOVIDO_PELO_PSP"
    )
}
fn rec_status(s: &str) -> bool {
    matches!(
        s,
        "CRIADA" | "APROVADA" | "REJEITADA" | "EXPIRADA" | "CANCELADA"
    )
}
/// Interpret decoded JSON with an explicit expected resource, never infer authorization.
/// This subset excludes Pix Saque/Troco, full OpenAPI validation and JWS verification.
pub fn inspect_json(input: &str, kind: PayloadKind, context: Context) -> R<SemanticPayload> {
    if input.len() > 65536 {
        return Err("JSON exceeds inspection limit");
    }
    let root: Unique =
        serde_json::from_str(input).map_err(|_| "malformed or duplicate-key JSON")?;
    let o = root.0.as_object().ok_or("root must be object")?;
    let cal = obj(o, "calendario")?;
    let mut x = SemanticPayload {
        kind,
        reference: String::new(),
        declared_status: String::new(),
        revision: None,
        original_cents: None,
        final_cents: None,
        editable_amount: false,
        expiry_seconds: None,
        recurrence_minimum_cents: None,
        recurrence_periodicity: None,
    };
    if kind == PayloadKind::Rec {
        if context != Context::Compound || o.contains_key("txid") || o.contains_key("revisao") {
            return Err("recurrence context mismatch");
        }
        let id = string(o, "idRec")?;
        if id.len() != 29
            || !id.is_ascii()
            || !matches!(&id[..2], "RR" | "RN" | "CR" | "CN")
            || !id[2..10]
                .bytes()
                .all(|b| b.is_ascii_digit() || b.is_ascii_uppercase())
            || !id[10..18].bytes().all(|b| b.is_ascii_digit())
            || !id[18..].bytes().all(|b| b.is_ascii_alphanumeric())
        {
            return Err("invalid idRec");
        }
        let day = format!("{}-{}-{}", &id[10..14], &id[14..16], &id[16..18]);
        if !date(&day) {
            return Err("invalid idRec date");
        }
        let policy = string(o, "politicaRetentativa")?;
        if !matches!(
            (id.as_bytes()[1], policy),
            (b'R', "PERMITE_3R_7D") | (b'N', "NAO_PERMITE")
        ) {
            return Err("retry policy mismatch");
        }
        let link = obj(o, "vinculo")?;
        string(link, "contrato")?;
        opt_string(link, "objeto")?;
        party(obj(link, "devedor")?, true)?;
        let first = date_field(cal, "dataInicial")?;
        if let Some(last) = opt_string(cal, "dataFinal")? {
            if !date(last) || last < first {
                return Err("invalid recurrence end");
            }
        }
        x.recurrence_periodicity = Some(string(cal, "periodicidade")?.to_owned());
        if let Some(v) = opt_obj(o, "valor")? {
            x.original_cents = opt_money(v, "valorRec")?;
            x.recurrence_minimum_cents = opt_money(v, "valorMinimoRecebedor")?;
        }
        let receiver = obj(o, "recebedor")?;
        if !cnpj(string(receiver, "cnpj")?) || !digits(string(receiver, "ispbParticipante")?, 8) {
            return Err("invalid recurrence receiver");
        }
        string(receiver, "nome")?;
        let history = o
            .get("atualizacao")
            .and_then(Value::as_array)
            .filter(|a| !a.is_empty())
            .ok_or("missing recurrence history")?;
        for entry in history {
            let e = entry.as_object().ok_or("invalid history entry")?;
            let s = string(e, "status")?;
            if !rec_status(s) {
                return Err("unknown recurrence status");
            }
            ts(e, "data")?;
            x.declared_status = s.to_owned();
        }
        x.reference = id.to_owned();
        return Ok(x);
    }
    if o.contains_key("idRec") || o.contains_key("vinculo") {
        return Err("charge context mismatch");
    }
    x.revision = Some(integer(o, "revisao")?);
    ts(cal, "criacao")?;
    ts(cal, "apresentacao")?;
    let key = string(o, "chave")?;
    if key.len() > 77 {
        return Err("key exceeds local inspection limit");
    }
    let txid = string(o, "txid")?;
    if !(26..=35).contains(&txid.len()) || !txid.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err("invalid dynamic txid");
    }
    x.reference = txid.to_owned();
    let status = string(o, "status")?;
    if !charge_status(status) {
        return Err("unknown charge status");
    }
    x.declared_status = status.to_owned();
    opt_string(o, "solicitacaoPagador")?;
    if let Some(infos) = o.get("infoAdicionais") {
        for item in infos.as_array().ok_or("invalid additional info")? {
            let i = item.as_object().ok_or("invalid additional info entry")?;
            string(i, "nome")?;
            string(i, "valor")?;
        }
    }
    let v = obj(o, "valor")?;
    if v.contains_key("retirada") {
        return Err("Pix Saque/Troco outside W2 subset");
    }
    match kind {
        PayloadKind::Cob => {
            if cal.contains_key("dataDeVencimento")
                || cal.contains_key("validadeAposVencimento")
                || v.contains_key("final")
                || ["abatimento", "desconto", "juros", "multa"]
                    .iter()
                    .any(|k| v.contains_key(*k))
            {
                return Err("mixed charge schema");
            }
            if let Some(p) = opt_obj(o, "devedor")? {
                party(p, false)?;
            }
            x.expiry_seconds = Some(opt_int(cal, "expiracao")?.unwrap_or(86400));
            let mode = opt_int(v, "modalidadeAlteracao")?.unwrap_or(0);
            if mode > 1 {
                return Err("invalid amount mode");
            }
            let n = money(string(v, "original")?)?;
            if n == 0 && mode == 0 {
                return Err("fixed zero amount");
            }
            x.original_cents = Some(n);
            x.editable_amount = mode == 1;
            if mode == 0 {
                x.final_cents = Some(n);
            }
        }
        PayloadKind::Cobv => {
            if cal.contains_key("expiracao") || v.contains_key("modalidadeAlteracao") {
                return Err("mixed charge schema");
            }
            date_field(cal, "dataDeVencimento")?;
            integer(cal, "validadeAposVencimento")?;
            party(obj(o, "devedor")?, true)?;
            let p = obj(o, "recebedor")?;
            party(p, true)?;
            for k in ["logradouro", "cidade", "uf", "cep"] {
                string(p, k)?;
            }
            opt_string(p, "nomeFantasia")?;
            x.original_cents = opt_money(v, "original")?;
            let f = money(string(v, "final")?)?;
            x.final_cents = Some(f);
            let [a, b, j, m] =
                ["abatimento", "desconto", "juros", "multa"].map(|k| opt_money(v, k));
            let (a, b, j, m) = (a?, b?, j?, m?);
            if [a, b, j, m].contains(&Some(0)) {
                return Err("zero adjustments must be omitted");
            }
            if let Some(n) = x.original_cents {
                let expected = n as i64 - a.unwrap_or(0) as i64 - b.unwrap_or(0) as i64
                    + j.unwrap_or(0) as i64
                    + m.unwrap_or(0) as i64;
                if expected != f as i64 {
                    return Err("inconsistent final amount");
                }
            }
        }
        PayloadKind::Rec => unreachable!(),
    }
    Ok(x)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn cob() -> Value {
        json!({"revisao":0,"calendario":{"criacao":"2026-11-25T10:00:00Z","apresentacao":"2026-11-25T10:01:00Z"},"valor":{"original":"12.34"},"chave":"example@example.com","txid":"ABCDEFGHIJKLMNOPQRSTUVWXYZ","status":"ATIVA"})
    }
    fn cobv() -> Value {
        let mut v = cob();
        v["calendario"]["dataDeVencimento"] = json!("2026-12-01");
        v["calendario"]["validadeAposVencimento"] = json!(30);
        v["devedor"] = json!({"nome":"DEMO"});
        v["recebedor"] =
            json!({"nome":"DEMO","logradouro":"TESTE","cidade":"TESTE","uf":"CE","cep":"00000000"});
        v["valor"] = json!({"original":"12.34","desconto":"1.00","juros":"0.50","final":"11.84"});
        v
    }
    fn rec() -> Value {
        json!({"idRec":"RN1234567820261125ABCDEFGHIJK","vinculo":{"contrato":"DEMO","devedor":{"nome":"TESTE"}},"calendario":{"dataInicial":"2026-12-01","periodicidade":"MENSAL"},"valor":{"valorRec":"10.00"},"recebedor":{"cnpj":"12ABC34501DE35","nome":"TESTE","ispbParticipante":"12345678"},"politicaRetentativa":"NAO_PERMITE","atualizacao":[{"status":"CRIADA","data":"2026-11-25T10:00:00Z"}]})
    }
    fn check(v: &Value, k: PayloadKind) -> R<SemanticPayload> {
        inspect_json(
            &v.to_string(),
            k,
            if k == PayloadKind::Rec {
                Context::Compound
            } else {
                Context::Dynamic
            },
        )
    }
    #[test]
    fn immediate() {
        let x = check(&cob(), PayloadKind::Cob).unwrap();
        assert_eq!(x.expiry_seconds, Some(86400));
        assert_eq!(x.final_cents, Some(1234));
        assert!(!x.is_verified());
    }
    #[test]
    fn editable() {
        let mut v = cob();
        v["valor"] = json!({"original":"0.00","modalidadeAlteracao":1});
        let x = check(&v, PayloadKind::Cob).unwrap();
        assert!(x.editable_amount);
        assert_eq!(x.final_cents, None);
    }
    #[test]
    fn fixed_zero() {
        let mut v = cob();
        v["valor"]["original"] = json!("0.00");
        assert!(check(&v, PayloadKind::Cob).is_err());
    }
    #[test]
    fn money_types() {
        for a in [
            json!(12.34),
            json!("1.1"),
            json!("-1.00"),
            json!("12345678901.00"),
        ] {
            let mut v = cob();
            v["valor"]["original"] = a;
            assert!(check(&v, PayloadKind::Cob).is_err());
        }
    }
    #[test]
    fn due() {
        assert_eq!(
            check(&cobv(), PayloadKind::Cobv).unwrap().final_cents,
            Some(1184)
        );
    }
    #[test]
    fn inconsistent() {
        let mut v = cobv();
        v["valor"]["final"] = json!("99.99");
        assert!(check(&v, PayloadKind::Cobv).is_err());
    }
    #[test]
    fn optional_original() {
        let mut v = cobv();
        v["valor"].as_object_mut().unwrap().remove("original");
        assert_eq!(check(&v, PayloadKind::Cobv).unwrap().original_cents, None);
    }
    #[test]
    fn invalid_date() {
        let mut v = cobv();
        v["calendario"]["dataDeVencimento"] = json!("2026-02-29");
        assert!(check(&v, PayloadKind::Cobv).is_err());
    }
    #[test]
    fn wrong_resource() {
        assert!(check(&cobv(), PayloadKind::Cob).is_err());
        assert!(check(&cob(), PayloadKind::Cobv).is_err());
    }
    #[test]
    fn duplicate_nested() {
        let s = cob().to_string().replace(
            "\"original\":\"12.34\"",
            "\"original\":\"12.34\",\"original\":\"99.99\"",
        );
        assert!(inspect_json(&s, PayloadKind::Cob, Context::Dynamic).is_err());
    }
    #[test]
    fn party_exclusion() {
        let mut v = cob();
        v["devedor"] = json!({"cpf":"12345678900","cnpj":"12345678900000","nome":"X"});
        assert!(check(&v, PayloadKind::Cob).is_err());
    }
    #[test]
    fn recurrence() {
        let x = check(&rec(), PayloadKind::Rec).unwrap();
        assert_eq!(x.original_cents, Some(1000));
        assert_eq!(x.declared_status, "CRIADA");
        assert!(!x.is_verified());
    }
    #[test]
    fn recurrence_policy() {
        let mut v = rec();
        v["politicaRetentativa"] = json!("PERMITE_3R_7D");
        assert!(check(&v, PayloadKind::Rec).is_err());
    }
    #[test]
    fn recurrence_requires_compound() {
        assert!(inspect_json(&rec().to_string(), PayloadKind::Rec, Context::Dynamic).is_err());
    }
    #[test]
    fn declared_status_not_evidence() {
        let mut v = cob();
        v["status"] = json!("CONCLUIDA");
        assert!(!check(&v, PayloadKind::Cob).unwrap().is_verified());
    }
    #[test]
    fn rejects_withdrawal() {
        let mut v = cob();
        v["valor"]["retirada"] = json!({"saque":{"valor":"10.00"}});
        assert!(inspect_json(&v.to_string(), PayloadKind::Cob, Context::Compound).is_err());
    }
}
