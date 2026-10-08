//! Customer-only API. Administrative Economy and credit issuance are not HTTP routes.
use crate::{billing::Store, economy::EconomyCheckout, Allowance, Evaluation};
use axum::{
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    response::Html,
    routing::{get, post},
    Json, Router,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{fs, io::Write, path::{Path, PathBuf}, time::{SystemTime, UNIX_EPOCH}};

type ApiError = (StatusCode, Json<Value>);
type ApiResult = Result<Json<Value>, ApiError>;
#[derive(Clone)]
struct ApiState { home: Option<PathBuf> }
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientKey { studio: String }

fn error(status: StatusCode, code: &str) -> ApiError {
    (status, Json(json!({"error": code})))
}
fn valid_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 80 && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-.:".contains(&b))
}
/// Operator command: returns a new secret once; only its hash is saved on disk.
/// `home` is the S1 directory, not the parent node directory.
pub fn issue_client_key(home: &Path, studio: &str) -> Result<String, Box<dyn std::error::Error>> {
    if !valid_id(studio) { return Err("invalid studio identifier".into()); }
    let directory = home.join("client-keys");
    fs::create_dir_all(&directory)?;
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
    }
    let mut random = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut random);
    let token = hex::encode(random);
    let hash = blake3::hash(token.as_bytes()).to_hex().to_string();
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)] {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(directory.join(format!("{hash}.json")))?;
    file.write_all(&serde_json::to_vec(&ClientKey { studio: studio.into() })?)?;
    file.sync_all()?;
    Ok(token)
}
fn authenticate(state: &ApiState, headers: &HeaderMap) -> Result<(PathBuf, String), ApiError> {
    let home = state.home.as_ref().ok_or_else(|| error(StatusCode::SERVICE_UNAVAILABLE, "node_not_configured"))?;
    let token = headers.get("authorization").and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer "))
        .filter(|v| v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| error(StatusCode::UNAUTHORIZED, "client_key_required"))?;
    let hash = blake3::hash(token.as_bytes()).to_hex().to_string();
    let record: ClientKey = fs::read(home.join("s1/client-keys").join(format!("{hash}.json")))
        .ok().and_then(|b| serde_json::from_slice(&b).ok())
        .filter(|r: &ClientKey| valid_id(&r.studio))
        .ok_or_else(|| error(StatusCode::UNAUTHORIZED, "invalid_client_key"))?;
    Ok((home.clone(), record.studio))
}
async fn blocking<T: Serialize + Send + 'static>(work: impl FnOnce() -> Result<T, String> + Send + 'static) -> ApiResult {
    match tokio::task::spawn_blocking(work).await {
        Ok(Ok(value)) => Ok(Json(serde_json::to_value(value).map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "response_failed"))?)),
        Ok(Err(_)) => Err(error(StatusCode::SERVICE_UNAVAILABLE, "checkout_or_ledger_unavailable")),
        Err(_) => Err(error(StatusCode::INTERNAL_SERVER_ERROR, "operation_failed")),
    }
}
/// Read-only demo. Checkout is unavailable until an operator explicitly supplies a node home.
pub fn router() -> Router { build(ApiState { home: None }) }
/// Shares the node's S1 ledger and the existing Economy settlement verifier.
pub fn configured_router(home: PathBuf) -> Router { build(ApiState { home: Some(home) }) }
fn build(state: ApiState) -> Router {
    Router::new()
        .route("/", get(|| async { Html(include_str!("../../../apps/mycelium-s1-portal/dist/index.html")) }))
        .route("/api/health", get(health))
        .route("/api/catalog", get(|| async { Json(json!({"packs": crate::economy::CREDIT_PACKS, "currency": "USDC", "chain_id": 8453})) }))
        .route("/api/evaluate", post(evaluate))
        .route("/api/client/balance", get(balance))
        .route("/api/client/tickets", post(reserve))
        .route("/api/checkout/quote", post(quote))
        .route("/api/checkout/confirm", post(confirm))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(axum::middleware::map_response(|mut response: axum::response::Response| async move {
            let headers = response.headers_mut();
            headers.insert("cache-control", "no-store".parse().unwrap());
            headers.insert("x-content-type-options", "nosniff".parse().unwrap());
            headers.insert("referrer-policy", "same-origin".parse().unwrap());
            response
        }))
        .with_state(state)
}
async fn health(State(state): State<ApiState>) -> Json<Value> {
    Json(json!({"runtime":"mycelium-s1", "execution":"local", "payments":"requires_trusted_verifier", "client_api_configured":state.home.is_some(), "customer_auth":"bearer_key", "demo_metered":false}))
}
async fn evaluate(Json(r): Json<Evaluation>) -> ApiResult {
    r.model.evaluate(&r.features, &r.allowed)
        .map(|p| Json(json!({"probabilities":p,"execution":"local","metered":false})))
        .map_err(|_| error(StatusCode::BAD_REQUEST, "invalid_evaluation"))
}
async fn balance(State(state): State<ApiState>, headers: HeaderMap) -> ApiResult {
    let (home, studio) = authenticate(&state, &headers)?;
    blocking(move || {
        let store = Store::open(&home.join("s1")).map_err(|e| e.to_string())?;
        Ok(json!({"studio":studio,"evaluations":store.ledger.balances.get(&studio).copied().unwrap_or(0),"issuer_public_key":hex::encode(store.issuer.verifying_key().as_bytes())}))
    }).await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QuoteRequest { order_id: String, pack_id: String }
async fn quote(State(state): State<ApiState>, headers: HeaderMap, Json(r): Json<QuoteRequest>) -> ApiResult {
    let (home, studio) = authenticate(&state, &headers)?;
    if !valid_id(&r.order_id) || !valid_id(&r.pack_id) { return Err(error(StatusCode::BAD_REQUEST, "invalid_order")); }
    blocking(move || EconomyCheckout::new(home.join("s1"),home.join("economy")).quote(&studio,&r.order_id,&r.pack_id).map_err(|e| e.to_string())).await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfirmRequest { order_id: String, tx_hash: String }
async fn confirm(State(state): State<ApiState>, headers: HeaderMap, Json(r): Json<ConfirmRequest>) -> ApiResult {
    let (home, studio) = authenticate(&state, &headers)?;
    if !valid_id(&r.order_id) || r.tx_hash.len() != 66 || !r.tx_hash.starts_with("0x") || !r.tx_hash[2..].bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(error(StatusCode::BAD_REQUEST, "invalid_transaction"));
    }
    blocking(move || EconomyCheckout::new(home.join("s1"),home.join("economy")).confirm(&studio,&r.order_id,&r.tx_hash).map_err(|e| e.to_string())).await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReserveRequest { id: String, model: String, device: String, evaluations: u64, expires_at: u64 }
async fn reserve(State(state): State<ApiState>, headers: HeaderMap, Json(r): Json<ReserveRequest>) -> ApiResult {
    let (home, studio) = authenticate(&state, &headers)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR,"invalid_clock"))?.as_secs();
    if !valid_id(&r.id) || !valid_id(&r.model) || !valid_id(&r.device) || r.evaluations == 0 || r.expires_at <= now || r.expires_at > now.saturating_add(30*86400) {
        return Err(error(StatusCode::BAD_REQUEST, "invalid_allowance"));
    }
    blocking(move || {
        let mut store = Store::open(&home.join("s1")).map_err(|e| e.to_string())?;
        let ticket = store.ledger.reserve(Allowance { id:format!("{studio}:{}",r.id), studio:studio.clone(),model:r.model,device:r.device,evaluations:r.evaluations,expires_at:r.expires_at },&store.issuer,now)?;
        store.save().map_err(|e| e.to_string())?;
        Ok(json!({"ticket":ticket,"issuer_public_key":hex::encode(store.issuer.verifying_key().as_bytes()),"evaluations":store.ledger.balances.get(&studio).copied().unwrap_or(0)}))
    }).await
}
#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::{Body,to_bytes}, http::Request};
    use tower::ServiceExt;
    #[tokio::test]
    async fn customer_keys_isolate_balances_and_no_admin_routes() {
        let tmp = tempfile::tempdir().unwrap();
        let a = issue_client_key(&tmp.path().join("s1"),"alpha").unwrap();
        let b = issue_client_key(&tmp.path().join("s1"),"beta").unwrap();
        {
            let mut store = Store::open(&tmp.path().join("s1")).unwrap();
            store.ledger.credit("verified-test", "alpha", 77).unwrap();
            store.save().unwrap();
        }
        let app = configured_router(tmp.path().into());
        let response = app.clone().oneshot(Request::builder().uri("/api/client/balance").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(response.status(),StatusCode::UNAUTHORIZED);
        for (token,expected) in [(a,77),(b,0)] {
            let response = app.clone().oneshot(Request::builder().uri("/api/client/balance").header("authorization",format!("Bearer {token}")).body(Body::empty()).unwrap()).await.unwrap();
            assert_eq!(response.status(),StatusCode::OK);
            let value:Value = serde_json::from_slice(&to_bytes(response.into_body(),1024*1024).await.unwrap()).unwrap();
            assert_eq!(value["evaluations"],expected);
        }
        for path in ["/api/credit","/api/economy/credit","/api/economy/admin","/api/train"] {
            let response = app.clone().oneshot(Request::builder().uri(path).body(Body::empty()).unwrap()).await.unwrap();
            assert_eq!(response.status(),StatusCode::NOT_FOUND);
        }
    }
    #[tokio::test]
    async fn checkout_fails_closed_and_rejects_studio_injection() {
        let tmp = tempfile::tempdir().unwrap();
        let token = issue_client_key(&tmp.path().join("s1"),"alpha").unwrap();
        let app = configured_router(tmp.path().into());
        for (body,status) in [(json!({"order_id":"r1","pack_id":"1m"}),StatusCode::SERVICE_UNAVAILABLE),(json!({"order_id":"r1","pack_id":"1m","studio":"beta"}),StatusCode::UNPROCESSABLE_ENTITY)] {
            let response=app.clone().oneshot(Request::builder().uri("/api/checkout/quote").method("POST").header("content-type","application/json").header("authorization",format!("Bearer {token}")).body(Body::from(body.to_string())).unwrap()).await.unwrap();
            assert_eq!(response.status(),status);
        }
        assert!(!tmp.path().join("economy/payment-policy.json").exists());
        let ledger=Store::open(&tmp.path().join("s1")).unwrap();
        assert!(ledger.ledger.balances.is_empty());
    }
    #[tokio::test]
    async fn demo_has_bounded_payloads() {
        let response=router().oneshot(Request::builder().uri("/api/evaluate").method("POST").header("content-type","application/json").body(Body::from(" ".repeat(65537))).unwrap()).await.unwrap();
        assert_eq!(response.status(),StatusCode::PAYLOAD_TOO_LARGE);
    }
}
