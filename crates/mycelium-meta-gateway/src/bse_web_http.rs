//! W3: bounded, passive observation of synthetic HTTP exchanges.
//! Lab routes are deliberately not production API URLs. No network I/O here.
use crate::pix_json::{inspect_json, Context, PayloadKind};
use serde::Deserialize;

pub const MAX_TRACE_BYTES: usize = 262144;
const MAX_BODY_BYTES: usize = 65536;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Surface {
    Payload,
    Management,
    Callback,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resource {
    Cob,
    Cobv,
    Rec,
    Pix,
    Loc,
    LocRec,
    SolicRec,
    Cobr,
    Webhook,
    WebhookRec,
    WebhookCobr,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpClass {
    Success,
    Redirect,
    ClientError,
    ServerError,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyState {
    DecodedJson,
    InvalidJson,
    SignedEnvelopeNotVerified,
    UnsupportedContentType,
    MetadataOnly,
    NotInspected,
}
/// Redacted observation: no raw body, URL, token, personal identifier or amount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub surface: Surface,
    pub resource: Resource,
    pub http_status: u16,
    pub http_class: HttpClass,
    pub body_state: BodyState,
    pub declared_status: Option<String>,
    pub response_bytes: usize,
}
impl Observation {
    pub const fn is_verified(&self) -> bool {
        false
    }
}
/// Input deliberately has no headers, credentials or external destination.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Exchange {
    method: String,
    path: String,
    status: u16,
    #[serde(default)]
    content_type: String,
    #[serde(default)]
    body: String,
}
fn route(method: &str, path: &str) -> Result<(Surface, Resource), &'static str> {
    use Resource::*;
    if let Some(r) = path.strip_prefix("/lab/payload/") {
        if method != "GET" {
            return Err("payload route requires GET");
        }
        let r = match r {
            "cob" => Cob,
            "cobv" => Cobv,
            "rec" => Rec,
            _ => return Err("unknown lab payload route"),
        };
        return Ok((Surface::Payload, r));
    }
    if let Some(r) = path.strip_prefix("/lab/api/") {
        if !matches!(method, "GET" | "PUT" | "POST" | "PATCH" | "DELETE") {
            return Err("unsupported lab method");
        }
        // Fixed synthetic resource names only, never arbitrary identifiers.
        let r = r.strip_suffix("/fixture").unwrap_or(r);
        let r = match r {
            "cob" => Cob,
            "cobv" => Cobv,
            "rec" => Rec,
            "pix" => Pix,
            "loc" => Loc,
            "locRec" => LocRec,
            "solicrec" => SolicRec,
            "cobr" => Cobr,
            "webhook" => Webhook,
            "webhookrec" => WebhookRec,
            "webhookcobr" => WebhookCobr,
            _ => return Err("unknown lab management route"),
        };
        return Ok((Surface::Management, r));
    }
    if let Some(r) = path.strip_prefix("/lab/callback/") {
        if method != "POST" {
            return Err("callback route requires POST");
        }
        let r = match r {
            "pix" => Webhook,
            "rec" => WebhookRec,
            "cobr" => WebhookCobr,
            _ => return Err("unknown lab callback route"),
        };
        return Ok((Surface::Callback, r));
    }
    Err("outside synthetic lab routes")
}
fn content_type(s: &str) -> &str {
    s.split(';').next().unwrap_or("").trim()
}
/// Observe a completed synthetic request/response pair. Never sends the request,
/// follows redirects, verifies signatures or mutates a financial state.
pub fn observe_http_trace(input: &str) -> Result<Observation, &'static str> {
    if input.len() > MAX_TRACE_BYTES {
        return Err("trace exceeds limit");
    }
    let e: Exchange = serde_json::from_str(input).map_err(|_| "invalid trace envelope")?;
    if e.body.len() > MAX_BODY_BYTES || e.content_type.len() > 128 {
        return Err("trace field exceeds limit");
    }
    let (surface, resource) = route(&e.method, &e.path)?;
    let http_class = match e.status {
        200..=299 => HttpClass::Success,
        300..=399 => HttpClass::Redirect,
        400..=499 => HttpClass::ClientError,
        500..=599 => HttpClass::ServerError,
        _ => return Err("not a final HTTP status"),
    };
    let mut out = Observation {
        surface,
        resource,
        http_status: e.status,
        http_class,
        body_state: BodyState::NotInspected,
        declared_status: None,
        response_bytes: e.body.len(),
    };
    if http_class != HttpClass::Success {
        return Ok(out);
    }
    if surface != Surface::Payload {
        out.body_state = BodyState::MetadataOnly;
        return Ok(out);
    }
    if e.status != 200 {
        return Ok(out);
    }
    let ct = content_type(&e.content_type);
    if ct.eq_ignore_ascii_case("application/jose")
        || ct.eq_ignore_ascii_case("application/jose+json")
    {
        out.body_state = BodyState::SignedEnvelopeNotVerified;
        return Ok(out);
    }
    if !ct.eq_ignore_ascii_case("application/json") {
        out.body_state = BodyState::UnsupportedContentType;
        return Ok(out);
    }
    let (kind, context) = match resource {
        Resource::Cob => (PayloadKind::Cob, Context::Dynamic),
        Resource::Cobv => (PayloadKind::Cobv, Context::Dynamic),
        Resource::Rec => (PayloadKind::Rec, Context::Compound),
        _ => unreachable!(),
    };
    match inspect_json(&e.body, kind, context) {
        Ok(p) => {
            out.body_state = BodyState::DecodedJson;
            out.declared_status = Some(p.declared_status);
        }
        Err(_) => out.body_state = BodyState::InvalidJson,
    }
    Ok(out)
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn cob() -> String {
        json!({"revisao":0,"calendario":{"criacao":"2026-11-25T10:00:00Z","apresentacao":"2026-11-25T10:01:00Z"},"valor":{"original":"12.34"},"chave":"fixture@example.invalid","txid":"ABCDEFGHIJKLMNOPQRSTUVWXYZ","status":"ATIVA"}).to_string()
    }
    fn cobv() -> String {
        let mut v: serde_json::Value = serde_json::from_str(&cob()).unwrap();
        v["calendario"]["dataDeVencimento"] = json!("2026-12-01");
        v["calendario"]["validadeAposVencimento"] = json!(30);
        v["devedor"] = json!({"nome":"DEMO"});
        v["recebedor"] =
            json!({"nome":"DEMO","logradouro":"TESTE","cidade":"TESTE","uf":"CE","cep":"00000000"});
        v["valor"] = json!({"original":"12.34","final":"12.34"});
        v.to_string()
    }
    fn rec() -> String {
        json!({"idRec":"RN1234567820261125ABCDEFGHIJK","vinculo":{"contrato":"DEMO","devedor":{"nome":"TESTE"}},"calendario":{"dataInicial":"2026-12-01","periodicidade":"MENSAL"},"valor":{"valorRec":"10.00"},"recebedor":{"cnpj":"12ABC34501DE35","nome":"TESTE","ispbParticipante":"12345678"},"politicaRetentativa":"NAO_PERMITE","atualizacao":[{"status":"CRIADA","data":"2026-11-25T10:00:00Z"}]}).to_string()
    }
    fn trace(m: &str, p: &str, s: u16, c: &str, b: &str) -> String {
        json!({"method":m,"path":p,"status":s,"content_type":c,"body":b}).to_string()
    }
    fn run(m: &str, p: &str, s: u16, c: &str, b: &str) -> Result<Observation, &'static str> {
        observe_http_trace(&trace(m, p, s, c, b))
    }
    #[test]
    fn cob_w2() {
        let x = run(
            "GET",
            "/lab/payload/cob",
            200,
            "application/json; charset=utf-8",
            &cob(),
        )
        .unwrap();
        assert_eq!(x.body_state, BodyState::DecodedJson);
        assert_eq!(x.declared_status.as_deref(), Some("ATIVA"));
        assert!(!x.is_verified());
    }
    #[test]
    fn cobv_w2() {
        assert_eq!(
            run("GET", "/lab/payload/cobv", 200, "application/json", &cobv())
                .unwrap()
                .body_state,
            BodyState::DecodedJson
        );
    }
    #[test]
    fn rec_w2() {
        assert_eq!(
            run("GET", "/lab/payload/rec", 200, "application/json", &rec())
                .unwrap()
                .declared_status
                .as_deref(),
            Some("CRIADA")
        );
    }
    #[test]
    fn route_type_mismatch() {
        assert_eq!(
            run("GET", "/lab/payload/cobv", 200, "application/json", &cob())
                .unwrap()
                .body_state,
            BodyState::InvalidJson
        );
    }
    #[test]
    fn no_external_routes() {
        for p in [
            "https://example.invalid/cob",
            "//example.invalid/cob",
            "/lab/payload/cob?x=1",
            "/lab/api/cob/123",
            "/lab/api/../cob",
        ] {
            assert!(run("GET", p, 200, "application/json", "").is_err());
        }
    }
    #[test]
    fn method_boundary() {
        assert!(run("POST", "/lab/payload/cob", 200, "application/json", "").is_err());
        assert!(run("GET", "/lab/callback/pix", 200, "application/json", "").is_err());
    }
    #[test]
    fn management_not_payload() {
        let x = run(
            "PUT",
            "/lab/api/cob/fixture",
            201,
            "application/json",
            &cob(),
        )
        .unwrap();
        assert_eq!(x.surface, Surface::Management);
        assert_eq!(x.body_state, BodyState::MetadataOnly);
        assert_eq!(x.declared_status, None);
    }
    #[test]
    fn callback_not_settlement() {
        let x = run(
            "POST",
            "/lab/callback/pix",
            200,
            "application/json",
            "{\"status\":\"CONCLUIDA\"}",
        )
        .unwrap();
        assert_eq!(x.surface, Surface::Callback);
        assert!(!x.is_verified());
        assert_eq!(x.declared_status, None);
    }
    #[test]
    fn status_classes() {
        for (s, k) in [
            (302, HttpClass::Redirect),
            (401, HttpClass::ClientError),
            (503, HttpClass::ServerError),
        ] {
            let x = run("GET", "/lab/payload/cob", s, "application/json", &cob()).unwrap();
            assert_eq!(x.http_class, k);
            assert_eq!(x.body_state, BodyState::NotInspected);
        }
        assert!(run("GET", "/lab/payload/cob", 100, "", "").is_err());
    }
    #[test]
    fn media_types() {
        for (c, k) in [
            ("application/jose", BodyState::SignedEnvelopeNotVerified),
            (
                "application/jose+json",
                BodyState::SignedEnvelopeNotVerified,
            ),
            ("text/html", BodyState::UnsupportedContentType),
        ] {
            assert_eq!(
                run("GET", "/lab/payload/cob", 200, c, &cob())
                    .unwrap()
                    .body_state,
                k
            );
        }
    }
    #[test]
    fn envelope_rejects_credentials_and_duplicates() {
        for s in [
            r#"{"method":"GET","path":"/lab/payload/cob","status":200,"authorization":"secret"}"#,
            r#"{"method":"GET","method":"POST","path":"/lab/payload/cob","status":200}"#,
        ] {
            assert!(observe_http_trace(s).is_err());
        }
    }
    #[test]
    fn bounded() {
        assert!(run(
            "GET",
            "/lab/payload/cob",
            200,
            "application/json",
            &"x".repeat(MAX_BODY_BYTES + 1)
        )
        .is_err());
        assert!(observe_http_trace(&" ".repeat(MAX_TRACE_BYTES + 1)).is_err());
    }
    #[test]
    fn redaction() {
        let x = run("GET", "/lab/payload/cob", 200, "application/json", &cob()).unwrap();
        let s = format!("{x:?}");
        for secret in [
            "fixture@example.invalid",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "12.34",
        ] {
            assert!(!s.contains(secret));
        }
    }
    #[test]
    fn invalid_duplicate_payload() {
        let b = cob().replace(
            "\"original\":\"12.34\"",
            "\"original\":\"12.34\",\"original\":\"99.99\"",
        );
        assert_eq!(
            run("GET", "/lab/payload/cob", 200, "application/json", &b)
                .unwrap()
                .body_state,
            BodyState::InvalidJson
        );
    }
}
