//! Gateway HTTP para navegador comum: sites estáticos publicados como Plot.
//!
//! - `GET /site/<ContentId>/<caminho>` serve o arquivo `<caminho>` (padrão
//!   `index.html`) de um Plot **público** do Spore Bank local.
//! - `GET /myc/<endereço myc1…>/<caminho>` resolve o endereço Pkarr, pega o
//!   primeiro endpoint `Plot` anunciado e serve como acima.
//!
//! Plot ausente localmente: entra na fila `want_plot` (o organismo busca na
//! malha) e a resposta é `503 Retry-After`. O gateway nunca serve Plot
//! restrito, nunca segue URL recebida de terceiros e isola cada site com CSP
//! `sandbox` (origem opaca: um site não lê dados de outro nem do gateway).

use crate::HorizonTable;
use axum::extract::{Path, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use mycelium_core::ContentId;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const RESOLVE_TTL: Duration = Duration::from_secs(300);
const SITE_CSP: &str = "sandbox allow-scripts allow-forms allow-popups; \
    default-src 'self' data: blob: 'unsafe-inline'; connect-src 'self'; \
    form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

/// Cache endereço → ContentId (evita consultar relays a cada requisição).
static RESOLVED: Mutex<Option<HashMap<String, (ContentId, Instant)>>> = Mutex::new(None);

pub(crate) async fn site_root(Path(id): Path<String>) -> Response {
    Redirect::permanent(&format!("/site/{id}/")).into_response()
}

pub(crate) async fn site_index(State(table): State<HorizonTable>, Path(id): Path<String>) -> Response {
    serve_site(&table, &id, "")
}

pub(crate) async fn site_path(
    State(table): State<HorizonTable>,
    Path((id, path)): Path<(String, String)>,
) -> Response {
    serve_site(&table, &id, &path)
}

pub(crate) async fn myc_root(Path(addr): Path<String>) -> Response {
    Redirect::permanent(&format!("/myc/{addr}/")).into_response()
}

pub(crate) async fn myc_index(State(table): State<HorizonTable>, Path(addr): Path<String>) -> Response {
    serve_myc(&table, &addr, "").await
}

pub(crate) async fn myc_path(
    State(table): State<HorizonTable>,
    Path((addr, path)): Path<(String, String)>,
) -> Response {
    serve_myc(&table, &addr, &path).await
}

async fn serve_myc(table: &HorizonTable, addr: &str, path: &str) -> Response {
    match resolve_plot(addr).await {
        Ok(cid) => serve_cid(table, cid, path),
        Err(e) => (StatusCode::BAD_GATEWAY, format!("endereço não resolvido: {e}")).into_response(),
    }
}

fn serve_site(table: &HorizonTable, id: &str, path: &str) -> Response {
    if id.len() != 66 || !id.starts_with("Qm") {
        return (StatusCode::BAD_REQUEST, "ContentId inválido (Qm + 64 hex)").into_response();
    }
    match id.parse::<ContentId>() {
        Ok(cid) => serve_cid(table, cid, path),
        Err(_) => (StatusCode::BAD_REQUEST, "ContentId inválido").into_response(),
    }
}

fn serve_cid(table: &HorizonTable, cid: ContentId, path: &str) -> Response {
    let Some(home) = table.read().unwrap().get_home().map(|h| h.to_path_buf()) else {
        return (StatusCode::NOT_FOUND, "home não configurado").into_response();
    };
    let bank = match mycelium_sporebank::SporeBank::open(&home) {
        Ok(b) => b,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("spore bank: {e}")).into_response(),
    };
    let Some(plot) = bank.recall(&cid) else {
        table.write().unwrap().want_plot(cid);
        let mut r = (StatusCode::SERVICE_UNAVAILABLE, "buscando o site na malha; recarregue em instantes")
            .into_response();
        r.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from_static("5"));
        return r;
    };
    if !plot.is_public() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(wanted) = normalize(path) else {
        return (StatusCode::BAD_REQUEST, "caminho inválido").into_response();
    };
    let leaf = plot
        .leaves
        .iter()
        .find(|l| l.path.trim_start_matches("./") == wanted)
        .or_else(|| {
            // diretório → index.html
            let idx = if wanted.is_empty() {
                "index.html".to_string()
            } else {
                format!("{}/index.html", wanted.trim_end_matches('/'))
            };
            plot.leaves.iter().find(|l| l.path.trim_start_matches("./") == idx)
        });
    match leaf {
        Some(l) => {
            let mut r = (StatusCode::OK, l.content.clone()).into_response();
            let h = r.headers_mut();
            h.insert(header::CONTENT_TYPE, HeaderValue::from_static(mime_for(&l.path)));
            h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(SITE_CSP));
            // conteúdo endereçado por hash: imutável
            h.insert(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=31536000, immutable"));
            r
        }
        None => (StatusCode::NOT_FOUND, "arquivo não existe neste Plot").into_response(),
    }
}

/// Recusa `..`, componentes vazios estranhos e caminhos absolutos.
fn normalize(path: &str) -> Option<String> {
    let mut out = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => continue,
            ".." => return None,
            p if p.contains('\\') || p.contains('\0') => return None,
            p => out.push(p),
        }
    }
    let mut s = out.join("/");
    if path.ends_with('/') && !s.is_empty() {
        s.push('/');
    }
    Some(s)
}

fn mime_for(path: &str) -> &'static str {
    let ext = path.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json",
        "txt" | "md" => "text/plain; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "wasm" => "application/wasm",
        "woff2" => "font/woff2",
        "pdf" => "application/pdf",
        _ => "application/octet-stream",
    }
}

/// Resolve `myc1…` → ContentId do primeiro endpoint Plot. Transporte:
/// `MYCELIUM_GATEWAY_SOCKS` (loopback) se definido, senão direto — o IP de
/// um gateway público já é público.
async fn resolve_plot(addr: &str) -> Result<ContentId, String> {
    {
        let cache = RESOLVED.lock().unwrap();
        if let Some((cid, at)) = cache.as_ref().and_then(|c| c.get(addr)) {
            if at.elapsed() < RESOLVE_TTL {
                return Ok(*cid);
            }
        }
    }
    use mycelium_pkarr::{now_secs, open, Capability, Endpoint, RelayClient, Transport, DEFAULT_RELAYS};
    let cap = Capability::from_address(addr).map_err(|e| e.to_string())?;
    let transport = match std::env::var("MYCELIUM_GATEWAY_SOCKS") {
        Ok(v) if !v.is_empty() => Transport::Anonymous {
            socks5: v.parse().map_err(|e| format!("MYCELIUM_GATEWAY_SOCKS: {e}"))?,
        },
        _ => Transport::DirectRevealsIp,
    };
    let relays: Vec<String> = DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect();
    let client = RelayClient::new(&relays, transport).map_err(|e| e.to_string())?;
    let now = now_secs();
    let mut last = String::from("sem resposta");
    for key in cap.lookup_keys(now).map_err(|e| e.to_string())? {
        let packet = match client.resolve(&key).await {
            Ok(p) => p,
            Err(e) => {
                last = e.to_string();
                continue;
            }
        };
        let record = open(&cap, &packet, now).map_err(|e| e.to_string())?;
        let cid = record
            .endpoints
            .iter()
            .find_map(|e| match e {
                Endpoint::Plot { content_id } => format!("Qm{content_id}").parse::<ContentId>().ok(),
                _ => None,
            })
            .ok_or("o endereço não anuncia nenhum Plot")?;
        let mut cache = RESOLVED.lock().unwrap();
        let map = cache.get_or_insert_with(HashMap::new);
        if map.len() > 1024 {
            map.clear();
        }
        map.insert(addr.to_string(), (cid, Instant::now()));
        return Ok(cid);
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traversal_refused() {
        assert_eq!(normalize("a/b.html").as_deref(), Some("a/b.html"));
        assert_eq!(normalize("").as_deref(), Some(""));
        assert_eq!(normalize("docs/").as_deref(), Some("docs/"));
        assert!(normalize("../etc/passwd").is_none());
        assert!(normalize("a/../../b").is_none());
        assert!(normalize("a\\b").is_none());
    }
}
