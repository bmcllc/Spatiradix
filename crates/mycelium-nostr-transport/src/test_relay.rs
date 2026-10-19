//! Relay Nostr mínimo em memória para testes (feature `test-relay`).
//!
//! Implementa o suficiente de NIP-01 para o transporte: `EVENT` (com `OK`),
//! `REQ`/`EOSE`/`CLOSE`, filtros `ids`/`authors`/`kinds`/`#x`/`since`/`until`/
//! `limit` e substituição de eventos endereçáveis (kinds 30000–39999 por
//! `pubkey`+`kind`+`d`). Opcionalmente aplica rate-limit por conexão e limite
//! de tamanho, como os relays públicos, e conta o que recebeu para os testes
//! medirem eventos por quadro. Não verifica assinaturas.

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio_tungstenite::tungstenite::Message;

/// Comportamento do relay de teste.
#[derive(Debug, Clone)]
pub struct RelayOptions {
    /// `Some((rajada, por_segundo))`: token bucket por conexão; excedente
    /// recebe `OK false "rate-limited: ..."` e não é guardado nem repassado.
    pub rate_limit: Option<(u32, u32)>,
    /// Tamanho máximo do frame `["EVENT", ...]` aceite.
    pub max_event_bytes: usize,
    /// Aceita o WebSocket mas nunca responde nada (relay pendurado).
    pub blackhole: bool,
}

impl Default for RelayOptions {
    fn default() -> Self {
        Self {
            rate_limit: None,
            max_event_bytes: 64 * 1024,
            blackhole: false,
        }
    }
}

/// Contadores do que o relay viu.
#[derive(Debug, Default)]
pub struct RelayStats {
    pub events_received: AtomicUsize,
    pub events_accepted: AtomicUsize,
    pub events_rate_limited: AtomicUsize,
    pub events_too_large: AtomicUsize,
    pub reqs: AtomicUsize,
    pub connections: AtomicUsize,
    /// Eventos aceites por kind.
    pub by_kind: Mutex<HashMap<u64, usize>>,
    /// Filtros de cada `REQ` recebido (ordem de chegada).
    pub req_filters: Mutex<Vec<Value>>,
}

impl RelayStats {
    pub fn accepted_of_kind(&self, kind: u64) -> usize {
        self.by_kind.lock().unwrap().get(&kind).copied().unwrap_or(0)
    }
}

/// Relay em execução; para quando o valor é descartado.
pub struct LocalRelay {
    pub url: String,
    pub stats: Arc<RelayStats>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for LocalRelay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Store {
    events: Vec<Value>,
}

impl LocalRelay {
    pub async fn spawn() -> Self {
        Self::spawn_with(RelayOptions::default()).await
    }

    pub async fn spawn_with(opts: RelayOptions) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind relay");
        let url = format!("ws://{}", listener.local_addr().expect("addr"));
        let stats = Arc::new(RelayStats::default());
        let store = Arc::new(Mutex::new(Store { events: Vec::new() }));
        let (bus, _) = broadcast::channel::<Arc<Value>>(4096);
        let stats_bg = Arc::clone(&stats);
        let task = tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let opts = opts.clone();
                let stats = Arc::clone(&stats_bg);
                let store = Arc::clone(&store);
                let bus = bus.clone();
                tokio::spawn(async move {
                    let Ok(ws) = tokio_tungstenite::accept_async(tcp).await else {
                        return;
                    };
                    stats.connections.fetch_add(1, Ordering::Relaxed);
                    serve(ws, opts, stats, store, bus).await;
                });
            }
        });
        Self { url, stats, task }
    }
}

async fn serve(
    ws: tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    opts: RelayOptions,
    stats: Arc<RelayStats>,
    store: Arc<Mutex<Store>>,
    bus: broadcast::Sender<Arc<Value>>,
) {
    let (mut sink, mut stream) = ws.split();
    let mut subs: HashMap<String, Vec<Value>> = HashMap::new();
    let mut live = bus.subscribe();
    let mut tokens = opts.rate_limit.map(|(burst, _)| burst as f64).unwrap_or(0.0);
    let mut last_refill = Instant::now();

    loop {
        tokio::select! {
            msg = stream.next() => {
                let text = match msg {
                    Some(Ok(Message::Text(t))) => t.to_string(),
                    Some(Ok(Message::Ping(p))) => {
                        let _ = sink.send(Message::Pong(p)).await;
                        continue;
                    }
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    Some(Ok(_)) => continue,
                };
                if opts.blackhole {
                    if let Ok(Value::Array(arr)) = serde_json::from_str::<Value>(&text) {
                        if arr.first().and_then(Value::as_str) == Some("REQ") {
                            stats.reqs.fetch_add(1, Ordering::Relaxed);
                            if let Some(f) = arr.get(2) {
                                stats.req_filters.lock().unwrap().push(f.clone());
                            }
                        }
                    }
                    continue;
                }
                let Ok(Value::Array(arr)) = serde_json::from_str::<Value>(&text) else {
                    continue;
                };
                match arr.first().and_then(Value::as_str) {
                    Some("EVENT") => {
                        let Some(ev) = arr.get(1).cloned() else { continue };
                        let id = ev["id"].as_str().unwrap_or("").to_string();
                        stats.events_received.fetch_add(1, Ordering::Relaxed);
                        if text.len() > opts.max_event_bytes {
                            stats.events_too_large.fetch_add(1, Ordering::Relaxed);
                            let _ = sink.send(ok(&id, false, "invalid: event too large")).await;
                            continue;
                        }
                        if let Some((burst, per_sec)) = opts.rate_limit {
                            let now = Instant::now();
                            tokens = (tokens
                                + now.duration_since(last_refill).as_secs_f64() * per_sec as f64)
                                .min(burst as f64);
                            last_refill = now;
                            if tokens < 1.0 {
                                stats.events_rate_limited.fetch_add(1, Ordering::Relaxed);
                                let _ = sink
                                    .send(ok(&id, false, "rate-limited: slow down there chief"))
                                    .await;
                                continue;
                            }
                            tokens -= 1.0;
                        }
                        let (accepted, why) = store_event(&store, &ev);
                        let _ = sink.send(ok(&id, accepted, why)).await;
                        if accepted {
                            stats.events_accepted.fetch_add(1, Ordering::Relaxed);
                            let kind = ev["kind"].as_u64().unwrap_or(0);
                            *stats.by_kind.lock().unwrap().entry(kind).or_default() += 1;
                            let _ = bus.send(Arc::new(ev));
                        }
                    }
                    Some("REQ") => {
                        let Some(sub_id) = arr.get(1).and_then(Value::as_str) else { continue };
                        let filters: Vec<Value> = arr[2..].to_vec();
                        stats.reqs.fetch_add(1, Ordering::Relaxed);
                        stats.req_filters.lock().unwrap().extend(filters.iter().cloned());
                        let stored = query(&store, &filters);
                        for ev in stored {
                            let _ = sink.send(text_msg(json!(["EVENT", sub_id, ev]))).await;
                        }
                        let _ = sink.send(text_msg(json!(["EOSE", sub_id]))).await;
                        subs.insert(sub_id.to_string(), filters);
                    }
                    Some("CLOSE") => {
                        if let Some(sub_id) = arr.get(1).and_then(Value::as_str) {
                            subs.remove(sub_id);
                        }
                    }
                    _ => {}
                }
            }
            ev = live.recv() => {
                let ev = match ev {
                    Ok(ev) => ev,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => break,
                };
                for (sub_id, filters) in &subs {
                    if filters.iter().any(|f| matches(f, &ev)) {
                        let _ = sink.send(text_msg(json!(["EVENT", sub_id, *ev]))).await;
                    }
                }
            }
        }
    }
}

fn text_msg(v: Value) -> Message {
    Message::Text(v.to_string())
}

fn ok(id: &str, accepted: bool, why: &str) -> Message {
    text_msg(json!(["OK", id, accepted, why]))
}

fn d_tag(ev: &Value) -> String {
    ev["tags"]
        .as_array()
        .and_then(|tags| {
            tags.iter().find_map(|t| {
                let t = t.as_array()?;
                (t.first()?.as_str()? == "d").then(|| t.get(1)?.as_str().map(str::to_string))?
            })
        })
        .unwrap_or_default()
}

fn store_event(store: &Mutex<Store>, ev: &Value) -> (bool, &'static str) {
    let mut st = store.lock().unwrap();
    let id = ev["id"].as_str().unwrap_or("");
    if st.events.iter().any(|e| e["id"].as_str() == Some(id)) {
        return (true, "duplicate: already have this event");
    }
    let kind = ev["kind"].as_u64().unwrap_or(0);
    if (30000..40000).contains(&kind) {
        let d = d_tag(ev);
        let pk = ev["pubkey"].as_str().unwrap_or("");
        let created = ev["created_at"].as_u64().unwrap_or(0);
        if let Some(pos) = st.events.iter().position(|e| {
            e["kind"].as_u64() == Some(kind) && e["pubkey"].as_str() == Some(pk) && d_tag(e) == d
        }) {
            let old = &st.events[pos];
            let old_created = old["created_at"].as_u64().unwrap_or(0);
            let old_id = old["id"].as_str().unwrap_or("");
            // NIP-01: mais novo ganha; empate fica o de menor id.
            if old_created > created || (old_created == created && old_id < id) {
                return (false, "replaced: have newer event");
            }
            st.events.remove(pos);
        }
    }
    st.events.push(ev.clone());
    (true, "")
}

fn query(store: &Mutex<Store>, filters: &[Value]) -> Vec<Value> {
    let st = store.lock().unwrap();
    let mut out: Vec<Value> = Vec::new();
    for f in filters {
        let mut hits: Vec<&Value> = st.events.iter().filter(|e| matches(f, e)).collect();
        hits.sort_by_key(|e| std::cmp::Reverse(e["created_at"].as_u64().unwrap_or(0)));
        if let Some(limit) = f.get("limit").and_then(Value::as_u64) {
            hits.truncate(limit as usize);
        }
        for h in hits {
            if !out.iter().any(|o| o["id"] == h["id"]) {
                out.push(h.clone());
            }
        }
    }
    out
}

fn matches(f: &Value, ev: &Value) -> bool {
    let Some(obj) = f.as_object() else { return false };
    for (k, v) in obj {
        let ok = match k.as_str() {
            "ids" => in_list(v, &ev["id"]),
            "authors" => in_list(v, &ev["pubkey"]),
            "kinds" => in_list(v, &ev["kind"]),
            "since" => ev["created_at"].as_u64() >= v.as_u64(),
            "until" => ev["created_at"].as_u64() <= v.as_u64(),
            "limit" => true,
            tag if tag.starts_with('#') && tag.len() == 2 => {
                let name = &tag[1..];
                let wanted = v.as_array().cloned().unwrap_or_default();
                ev["tags"].as_array().is_some_and(|tags| {
                    tags.iter().any(|t| {
                        t.get(0).and_then(Value::as_str) == Some(name)
                            && t.get(1).is_some_and(|val| wanted.contains(val))
                    })
                })
            }
            _ => true,
        };
        if !ok {
            return false;
        }
    }
    true
}

fn in_list(list: &Value, x: &Value) -> bool {
    list.as_array().is_some_and(|l| l.contains(x))
}
