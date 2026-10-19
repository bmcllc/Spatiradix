//! Sessão WebSocket persistente a um relay Nostr.
//!
//! Uma tarefa por relay faz todo o I/O:
//! - **ritmo de publicação**: token bucket ([`RATE_MAX`] eventos/s, rajada
//!   [`BURST`]). Um `OK false "rate-limited..."` (ou NOTICE/CLOSED do mesmo
//!   teor) pausa as publicações com backoff exponencial, corta o ritmo pela
//!   metade e devolve o evento recusado à fila; o ritmo volta a subir depois
//!   de uma sequência de `OK true`. Assim o transporte não acumula violações
//!   até ser banido.
//! - **reconexão**: se o WebSocket cai, reconecta com backoff, refaz as
//!   subscrições (com `since` avançado) e republica o que ficou sem `OK`.
//!
//! Todo WebSocket sai por [`mycelium_nostr::net::connect_ws`] (proxy SOCKS5 no
//! modo anônimo).

use futures_util::{SinkExt, StreamExt};
use mycelium_nostr::NostrEvent;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::time::{Duration, Instant};
use tokio_tungstenite::tungstenite::Message;

/// Eventos por segundo em regime normal.
pub const RATE_MAX: f64 = 8.0;
/// Piso do ritmo depois de rate-limits sucessivos.
pub const RATE_MIN: f64 = 0.1;
/// Rajada permitida (handshake Noise + Yamux cabe nela).
pub const BURST: f64 = 10.0;
/// Reenvios de um evento recusado por rate-limit antes de desistir dele.
const MAX_REQUEUE: u8 = 5;
const PING_EVERY: Duration = Duration::from_secs(30);
/// Sem `OK` neste prazo o evento sai da lista de pendentes.
const PENDING_TTL: Duration = Duration::from_secs(60);

#[derive(Debug, Error)]
pub enum WsError {
    #[error("websocket: {0}")]
    Ws(String),
    #[error("fechado")]
    Closed,
}

/// Contadores da sessão (diagnóstico e testes).
#[derive(Debug, Default)]
pub struct RelayCounters {
    pub sent: AtomicU64,
    pub accepted: AtomicU64,
    pub rate_limited: AtomicU64,
    pub rejected: AtomicU64,
    pub reconnects: AtomicU64,
}

struct SubEntry {
    filter: Value,
    tx: mpsc::UnboundedSender<NostrEvent>,
}

type Subs = Arc<Mutex<HashMap<String, SubEntry>>>;

enum Out {
    Event { id: String, payload: String },
    Req(String),
    Close(String),
}

/// Ligação WSS contínua: publish + múltiplas subscrições.
#[derive(Clone)]
pub struct PersistentRelay {
    out_tx: mpsc::UnboundedSender<Out>,
    subs: Subs,
    url: String,
    counters: Arc<RelayCounters>,
}

impl PersistentRelay {
    pub async fn connect(url: &str) -> Result<Self, WsError> {
        let (ws, _) = mycelium_nostr::net::connect_ws(url)
            .await
            .map_err(WsError::Ws)?;
        let (out_tx, out_rx) = mpsc::unbounded_channel();
        let subs: Subs = Arc::new(Mutex::new(HashMap::new()));
        let counters = Arc::new(RelayCounters::default());
        tokio::spawn(drive(
            url.to_string(),
            ws,
            out_rx,
            Arc::clone(&subs),
            Arc::clone(&counters),
        ));
        Ok(Self {
            out_tx,
            subs,
            url: url.to_string(),
            counters,
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    #[allow(dead_code)]
    pub fn counters(&self) -> &RelayCounters {
        &self.counters
    }

    /// Enfileira um evento (o envio respeita o ritmo do relay).
    pub fn publish(&self, event: &NostrEvent) -> Result<(), WsError> {
        let payload = json!(["EVENT", event]).to_string();
        self.out_tx
            .send(Out::Event {
                id: event.id.clone(),
                payload,
            })
            .map_err(|_| WsError::Closed)
    }

    /// Subscreve com filtro; devolve sub_id + receiver de eventos.
    /// A subscrição sobrevive a reconexões.
    pub fn subscribe(
        &self,
        filter: Value,
    ) -> Result<(String, mpsc::UnboundedReceiver<NostrEvent>), WsError> {
        let sub_id = format!("nt-{}", &hex::encode(rand_bytes())[..10]);
        let (tx, rx) = mpsc::unbounded_channel();
        self.subs
            .lock()
            .unwrap()
            .insert(sub_id.clone(), SubEntry { filter, tx });
        self.out_tx
            .send(Out::Req(sub_id.clone()))
            .map_err(|_| WsError::Closed)?;
        Ok((sub_id, rx))
    }

    #[allow(dead_code)]
    pub fn unsubscribe(&self, sub_id: &str) {
        if self.subs.lock().unwrap().remove(sub_id).is_some() {
            let _ = self.out_tx.send(Out::Close(sub_id.to_string()));
        }
    }
}

/// Token bucket com recuo multiplicativo em rate-limit.
struct Pacer {
    rate: f64,
    tokens: f64,
    last: Instant,
    pause_until: Instant,
    backoff: Duration,
    ok_streak: u32,
}

impl Pacer {
    fn new(now: Instant) -> Self {
        Self {
            rate: RATE_MAX,
            tokens: BURST,
            last: now,
            pause_until: now,
            backoff: Duration::from_secs(1),
            ok_streak: 0,
        }
    }

    fn refill(&mut self, now: Instant) {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + dt * self.rate).min(BURST);
        self.last = now;
    }

    fn next_slot(&mut self, now: Instant) -> Instant {
        self.refill(now);
        let at = if self.tokens >= 1.0 {
            now
        } else {
            now + Duration::from_secs_f64((1.0 - self.tokens) / self.rate)
        };
        at.max(self.pause_until)
    }

    fn consume(&mut self, now: Instant) {
        self.refill(now);
        self.tokens -= 1.0;
    }

    /// Um episódio por pausa: as recusas da mesma rajada não se acumulam.
    fn on_rate_limited(&mut self, now: Instant) {
        self.ok_streak = 0;
        if now < self.pause_until {
            return;
        }
        self.rate = (self.rate / 2.0).max(RATE_MIN);
        self.tokens = 0.0;
        self.last = now;
        self.pause_until = now + self.backoff;
        self.backoff = (self.backoff * 2).min(Duration::from_secs(30));
    }

    fn on_ok(&mut self) {
        self.ok_streak += 1;
        if self.ok_streak >= 20 {
            self.ok_streak = 0;
            self.rate = (self.rate * 1.5).min(RATE_MAX);
            self.backoff = (self.backoff / 2).max(Duration::from_secs(1));
        }
    }
}

fn is_rate_limit(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    m.starts_with("rate-limited")
        || m.contains("rate limit")
        || m.contains("rate-limit")
        || m.contains("slow down")
        || m.contains("too many")
        || m.contains("too fast")
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

struct Session {
    url: String,
    subs: Subs,
    counters: Arc<RelayCounters>,
    backlog: VecDeque<(String, String, u8)>,
    pending: HashMap<String, (String, u8, Instant)>,
    pacer: Pacer,
}

impl Session {
    fn handle_text(&mut self, text: &str) {
        let Ok(Value::Array(arr)) = serde_json::from_str::<Value>(text) else {
            return;
        };
        let s = |i: usize| arr.get(i).and_then(Value::as_str).unwrap_or("");
        match s(0) {
            "EVENT" if arr.len() >= 3 => {
                if let Ok(ev) = serde_json::from_value::<NostrEvent>(arr[2].clone()) {
                    if let Some(sub) = self.subs.lock().unwrap().get(s(1)) {
                        let _ = sub.tx.send(ev);
                    }
                }
            }
            "OK" => {
                let id = s(1);
                let accepted = arr.get(2).and_then(Value::as_bool).unwrap_or(false);
                let msg = s(3);
                let Some((payload, tries, _)) = self.pending.remove(id) else {
                    return;
                };
                if accepted || msg.starts_with("duplicate") {
                    self.counters.accepted.fetch_add(1, Ordering::Relaxed);
                    self.pacer.on_ok();
                } else if is_rate_limit(msg) {
                    self.counters.rate_limited.fetch_add(1, Ordering::Relaxed);
                    self.pacer.on_rate_limited(Instant::now());
                    tracing::debug!(relay = %self.url, %msg, "rate-limit: recuo e reenvio");
                    if tries < MAX_REQUEUE {
                        self.backlog.push_front((id.to_string(), payload, tries + 1));
                    }
                } else {
                    self.counters.rejected.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(relay = %self.url, %msg, "relay recusou evento");
                }
            }
            "NOTICE" | "CLOSED" => {
                let msg = if s(0) == "NOTICE" { s(1) } else { s(2) };
                if is_rate_limit(msg) {
                    self.pacer.on_rate_limited(Instant::now());
                }
                if msg.to_ascii_lowercase().contains("banned") || s(0) == "CLOSED" {
                    tracing::warn!(relay = %self.url, kind = s(0), %msg, "aviso do relay");
                } else {
                    tracing::debug!(relay = %self.url, %msg, "NOTICE");
                }
            }
            _ => {}
        }
    }

    fn req_frames(&self, lost_at: Option<u64>) -> Vec<String> {
        self.subs
            .lock()
            .unwrap()
            .iter()
            .map(|(id, sub)| {
                let mut filter = sub.filter.clone();
                // Depois de cair, pedir só o que pode ter passado durante a queda.
                if let (Some(lost), Some(since)) =
                    (lost_at, filter.get("since").and_then(Value::as_u64))
                {
                    filter["since"] = json!(since.max(lost.saturating_sub(30)));
                }
                json!(["REQ", id, filter]).to_string()
            })
            .collect()
    }
}

async fn drive(
    url: String,
    first: mycelium_nostr::net::WsStream,
    mut out_rx: mpsc::UnboundedReceiver<Out>,
    subs: Subs,
    counters: Arc<RelayCounters>,
) {
    let mut st = Session {
        url,
        subs,
        counters,
        backlog: VecDeque::new(),
        pending: HashMap::new(),
        pacer: Pacer::new(Instant::now()),
    };
    let mut conn = Some(first);
    let mut lost_at: Option<u64> = None;
    let mut retry = Duration::from_secs(1);

    loop {
        let ws = match conn.take() {
            Some(ws) => ws,
            None => {
                let wake = Instant::now() + retry;
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep_until(wake) => break,
                        out = out_rx.recv() => match out {
                            Some(Out::Event { id, payload }) => st.backlog.push_back((id, payload, 0)),
                            // REQ/CLOSE refeitos a partir de `subs` ao reconectar.
                            Some(_) => {}
                            None => return,
                        },
                    }
                }
                match mycelium_nostr::net::connect_ws(&st.url).await {
                    Ok((ws, _)) => {
                        st.counters.reconnects.fetch_add(1, Ordering::Relaxed);
                        tracing::info!(relay = %st.url, "relay reconectado");
                        retry = Duration::from_secs(1);
                        ws
                    }
                    Err(e) => {
                        tracing::debug!(relay = %st.url, error = %e, "reconexão falhou");
                        retry = (retry * 2).min(Duration::from_secs(60));
                        continue;
                    }
                }
            }
        };

        let (mut sink, mut stream) = ws.split();
        let mut alive = true;
        for req in st.req_frames(lost_at) {
            if sink.send(Message::Text(req)).await.is_err() {
                alive = false;
                break;
            }
        }
        // O que ficou sem OK na sessão anterior volta para a frente da fila.
        let mut stale: Vec<_> = st.pending.drain().collect();
        stale.sort_by_key(|(_, (_, _, t))| *t);
        for (id, (payload, tries, _)) in stale.into_iter().rev() {
            st.backlog.push_front((id, payload, tries));
        }
        let mut ping = tokio::time::interval(PING_EVERY);
        ping.tick().await;

        while alive {
            let slot = st.pacer.next_slot(Instant::now());
            tokio::select! {
                msg = stream.next() => match msg {
                    Some(Ok(Message::Text(t))) => st.handle_text(&t),
                    Some(Ok(Message::Ping(p))) => {
                        let _ = sink.send(Message::Pong(p)).await;
                    }
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => alive = false,
                    Some(Ok(_)) => {}
                },
                _ = tokio::time::sleep_until(slot), if !st.backlog.is_empty() => {
                    let Some((id, payload, tries)) = st.backlog.pop_front() else { continue };
                    if sink.send(Message::Text(payload.clone())).await.is_err() {
                        st.backlog.push_front((id, payload, tries));
                        alive = false;
                        continue;
                    }
                    st.pacer.consume(Instant::now());
                    st.counters.sent.fetch_add(1, Ordering::Relaxed);
                    st.pending.insert(id, (payload, tries, Instant::now()));
                }
                out = out_rx.recv() => match out {
                    Some(Out::Event { id, payload }) => st.backlog.push_back((id, payload, 0)),
                    Some(Out::Req(sub_id)) => {
                        let frame = st.subs.lock().unwrap().get(&sub_id)
                            .map(|s| json!(["REQ", sub_id, s.filter]).to_string());
                        if let Some(frame) = frame {
                            alive = sink.send(Message::Text(frame)).await.is_ok();
                        }
                    }
                    Some(Out::Close(sub_id)) => {
                        alive = sink.send(Message::Text(json!(["CLOSE", sub_id]).to_string())).await.is_ok();
                    }
                    None => {
                        let _ = sink.close().await;
                        return;
                    }
                },
                _ = ping.tick() => {
                    alive = sink.send(Message::Ping(Vec::new())).await.is_ok();
                    st.pending.retain(|_, (_, _, t)| t.elapsed() < PENDING_TTL);
                }
            }
        }
        tracing::warn!(relay = %st.url, "WebSocket do relay caiu — a reconectar");
        lost_at = Some(now_secs());
    }
}

fn rand_bytes() -> [u8; 8] {
    use rand::RngCore;
    let mut b = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_relay::{LocalRelay, RelayOptions};
    use mycelium_ghostid::GhostId;

    fn event(ghost: &GhostId, n: u32) -> NostrEvent {
        mycelium_nostr::seal_event(
            ghost,
            now_secs(),
            1,
            vec![vec!["d".into(), format!("t{n}")]],
            format!("msg {n}"),
        )
        .unwrap()
    }

    #[test]
    fn pacer_backs_off_once_per_episode_and_recovers() {
        let t0 = Instant::now();
        let mut p = Pacer::new(t0);
        p.on_rate_limited(t0);
        let r1 = p.rate;
        assert!(r1 < RATE_MAX);
        assert!(p.next_slot(t0) >= t0 + Duration::from_secs(1), "pausa de backoff");
        p.on_rate_limited(t0 + Duration::from_millis(10));
        assert_eq!(p.rate, r1, "mesma rajada não derruba o ritmo de novo");
        for _ in 0..20 {
            p.on_ok();
        }
        assert!(p.rate > r1);
    }

    #[test]
    fn rate_limit_messages_are_recognised() {
        assert!(is_rate_limit("rate-limited: slow down there chief"));
        assert!(is_rate_limit("you are noting too much, rate limit exceeded"));
        assert!(!is_rate_limit("invalid: bad signature"));
        assert!(!is_rate_limit("duplicate: have it"));
    }

    #[tokio::test]
    async fn rate_limited_relay_gets_every_event_without_bursting() {
        let relay = LocalRelay::spawn_with(RelayOptions {
            rate_limit: Some((3, 4)),
            ..Default::default()
        })
        .await;
        let r = PersistentRelay::connect(&relay.url).await.unwrap();
        let ghost = GhostId::spawn_quick(600).unwrap();
        for n in 0..15 {
            r.publish(&event(&ghost, n)).unwrap();
        }
        let deadline = Instant::now() + Duration::from_secs(20);
        while r.counters().accepted.load(Ordering::Relaxed) < 15 {
            assert!(Instant::now() < deadline, "eventos perdidos: {:?}", r.counters());
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let limited = relay.stats.events_rate_limited.load(Ordering::Relaxed);
        assert!(limited > 0, "o relay de teste devia ter limitado a rajada");
        // Recuo real: muito menos recusas do que eventos (sem martelar).
        assert!(limited <= 8, "recusas demais ({limited}) — não recuou");
    }

    #[tokio::test]
    async fn subscription_and_backlog_survive_reconnect() {
        // Relay que derruba a 1.ª conexão logo depois do REQ.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let backend = LocalRelay::spawn().await;
        let backend_url = backend.url.clone();
        tokio::spawn(async move {
            let mut first = true;
            while let Ok((tcp, _)) = listener.accept().await {
                let backend_url = backend_url.clone();
                let drop_it = std::mem::replace(&mut first, false);
                tokio::spawn(async move {
                    let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
                    if drop_it {
                        let _ = ws.next().await;
                        return; // derruba
                    }
                    let (up, _) = tokio_tungstenite::connect_async(&backend_url).await.unwrap();
                    let (mut up_tx, mut up_rx) = up.split();
                    let (mut dn_tx, mut dn_rx) = ws.split();
                    tokio::join!(
                        async { while let Some(Ok(m)) = dn_rx.next().await { let _ = up_tx.send(m).await; } },
                        async { while let Some(Ok(m)) = up_rx.next().await { let _ = dn_tx.send(m).await; } },
                    );
                });
            }
        });

        let r = PersistentRelay::connect(&url).await.unwrap();
        let ghost = GhostId::spawn_quick(600).unwrap();
        let (_sid, mut rx) = r
            .subscribe(json!({"kinds": [1], "authors": [ghost.nostr_pubkey_hex()], "since": now_secs() - 5}))
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        r.publish(&event(&ghost, 1)).unwrap();
        let got = tokio::time::timeout(Duration::from_secs(10), rx.recv())
            .await
            .expect("evento depois de reconectar")
            .unwrap();
        assert_eq!(got.content, "msg 1");
        assert!(r.counters().reconnects.load(Ordering::Relaxed) >= 1);
    }
}
