//! Conexão futures::AsyncRead/AsyncWrite sobre kind 39406 (framing fiável).
//!
//! ## Protocolo (v2)
//!
//! - **Hub**: uma ligação WebSocket por relay e uma única subscrição
//!   `{"kinds":[39401,39406], "#p":[eu], "since": agora-30}`; os eventos são
//!   repartidos por id de conexão. Nada de uma subscrição por conexão.
//! - **Dial**: o dialer sorteia um id de conexão de 8 bytes (`qel-conn`) e
//!   publica um 39401 `type: "dial"` para o peer. O listener responde com
//!   `type: "handshake-ack"` com o mesmo id. Só `dial` abre conexão do lado
//!   de quem escuta: um ack nunca é tomado por dial (antes cada ack de um nó
//!   era aceito pelo listener do outro como dial novo, num eco sem fim).
//! - **Dados**: 39406 com `qel-stream` = id da conexão, conteúdo
//!   NIP-44(base64(segmento)). Como o id é aleatório por conexão, dois dials
//!   simultâneos A→B e B→A não misturam quadros, e eventos de sessões
//!   antigas guardados no relay não entram numa conexão nova.
//! - Tag `d` aleatória por evento (39406 é endereçável: com `d` repetida o
//!   relay substituía/recusava quadros) e `expiration` NIP-40 para o relay
//!   poder descartá-los.

use crate::framing::{Frame, ReliableState, MAX_PAYLOAD, WINDOW_SIZE};
use crate::ws::PersistentRelay;
use base64::Engine as _;
use bytes::BytesMut;
use futures::{AsyncRead as FAsyncRead, AsyncWrite as FAsyncWrite};
use mycelium_ghostid::GhostId;
use mycelium_nostr::{
    decrypt_nip44_to_string, encrypt_nip44, seal_event, CandidateRelay, CandidateState,
    NostrEvent, KIND_QEL_BACKCHANNEL, KIND_QEL_CANDIDATE,
};
use pin_project::pin_project;
use serde_json::json;
use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};

/// Escritas pequenas (multistream, Noise, Yamux) juntam-se durante este prazo.
const COALESCE: Duration = Duration::from_millis(20);
/// ACK puro só se não houver dados de volta neste prazo.
const DELAYED_ACK: Duration = Duration::from_millis(100);
/// Bytes que o pump aceita do libp2p à frente da janela.
const SEND_BUFFER: usize = MAX_PAYLOAD * WINDOW_SIZE as usize;
/// Validade de um quadro no relay (NIP-40).
const FRAME_EXPIRATION_SECS: u64 = 600;

const DUPLEX_BUFFER: usize = 256 * 1024;

pub(crate) type ConnId = [u8; 8];

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn io_err(kind: io::ErrorKind, e: impl ToString) -> io::Error {
    io::Error::new(kind, e.to_string())
}

fn tag<'a>(ev: &'a NostrEvent, name: &str) -> Option<&'a str> {
    ev.tags
        .iter()
        .find(|t| t.len() >= 2 && t[0] == name)
        .map(|t| t[1].as_str())
}

fn parse_conn_id(s: &str) -> Option<ConnId> {
    hex::decode(s).ok()?.try_into().ok()
}

fn random_conn_id() -> ConnId {
    use rand::RngCore;
    let mut id = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut id);
    id
}

fn content_type(ev: &NostrEvent) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(&ev.content)
        .ok()?
        .get("type")?
        .as_str()
        .map(str::to_string)
}

/// Metade local da conexão (futures IO para libp2p).
#[pin_project]
pub struct NostrConnection {
    #[pin]
    inner: Compat<DuplexStream>,
}

impl FAsyncRead for NostrConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_read(cx, buf)
    }
}

impl FAsyncWrite for NostrConnection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_close(cx)
    }
}

/// Cria par (local futures-compat para libp2p, remoto tokio para o pump).
fn duplex_pair() -> (NostrConnection, DuplexStream) {
    let (a, b) = tokio::io::duplex(DUPLEX_BUFFER);
    (NostrConnection { inner: a.compat() }, b)
}

type Routes = Arc<Mutex<HashMap<ConnId, mpsc::UnboundedSender<NostrEvent>>>>;
type Acks = Arc<Mutex<HashMap<ConnId, oneshot::Sender<NostrEvent>>>>;
type DialSink = Arc<Mutex<Option<mpsc::UnboundedSender<NostrEvent>>>>;

/// Relay partilhado por listener e dials de um mesmo GhostID.
#[derive(Clone)]
pub(crate) struct Hub {
    pub(crate) relay: PersistentRelay,
    sk: [u8; 32],
    pk: String,
    routes: Routes,
    acks: Acks,
    dials: DialSink,
}

impl Hub {
    pub(crate) async fn connect(url: &str, ghost: &GhostId) -> Result<Self, io::Error> {
        let relay = PersistentRelay::connect(url)
            .await
            .map_err(|e| io_err(io::ErrorKind::ConnectionRefused, e))?;
        let pk = ghost.nostr_pubkey_hex();
        let filter = json!({
            "kinds": [KIND_QEL_CANDIDATE, KIND_QEL_BACKCHANNEL],
            "#p": [pk],
            "since": now_secs().saturating_sub(30),
        });
        let (_sub, mut rx) = relay
            .subscribe(filter)
            .map_err(|e| io_err(io::ErrorKind::BrokenPipe, e))?;
        let hub = Self {
            relay,
            sk: ghost.secret_key_bytes(),
            pk,
            routes: Arc::default(),
            acks: Arc::default(),
            dials: Arc::default(),
        };
        let (routes, acks, dials, me) = (
            Arc::clone(&hub.routes),
            Arc::clone(&hub.acks),
            Arc::clone(&hub.dials),
            hub.pk.clone(),
        );
        tokio::spawn(async move {
            while let Some(ev) = rx.recv().await {
                if ev.pubkey == me {
                    continue;
                }
                if ev.kind == KIND_QEL_BACKCHANNEL {
                    let Some(id) = tag(&ev, "qel-stream").and_then(parse_conn_id) else {
                        continue;
                    };
                    let mut routes = routes.lock().unwrap();
                    if let Some(tx) = routes.get(&id) {
                        if tx.send(ev).is_err() {
                            routes.remove(&id);
                        }
                    }
                } else if ev.kind == KIND_QEL_CANDIDATE {
                    let Some(id) = tag(&ev, "qel-conn").and_then(parse_conn_id) else {
                        continue;
                    };
                    match content_type(&ev).as_deref() {
                        Some("handshake-ack") => {
                            if let Some(tx) = acks.lock().unwrap().remove(&id) {
                                let _ = tx.send(ev);
                            }
                        }
                        Some("dial") => {
                            if let Some(tx) = dials.lock().unwrap().as_ref() {
                                let _ = tx.send(ev);
                            }
                        }
                        _ => {}
                    }
                }
            }
        });
        Ok(hub)
    }

    pub(crate) fn ghost(&self) -> Result<GhostId, io::Error> {
        GhostId::from_secret_bytes(self.sk, 3600).map_err(|e| io_err(io::ErrorKind::Other, e))
    }

    /// Passa a receber pedidos de dial (listener).
    pub(crate) fn listen(&self) -> mpsc::UnboundedReceiver<NostrEvent> {
        let (tx, rx) = mpsc::unbounded_channel();
        *self.dials.lock().unwrap() = Some(tx);
        rx
    }

    fn route(&self, id: ConnId) -> mpsc::UnboundedReceiver<NostrEvent> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.routes.lock().unwrap().insert(id, tx);
        rx
    }

    fn unroute(&self, id: &ConnId) {
        self.routes.lock().unwrap().remove(id);
        self.acks.lock().unwrap().remove(id);
    }

    fn publish_control(
        &self,
        peer_pk: &str,
        id: &ConnId,
        kind_label: &str,
        ttl: u64,
    ) -> Result<(), io::Error> {
        let ghost = self.ghost()?;
        let conn_hex = hex::encode(id);
        let now = now_secs();
        let tags = vec![
            vec!["qel".into(), "candidate-relay".into()],
            vec!["p".into(), peer_pk.to_string()],
            vec!["qel-conn".into(), conn_hex.clone()],
            vec!["expires".into(), (now + ttl).to_string()],
            vec!["expiration".into(), (now + ttl).to_string()],
            vec!["qel-backchannel".into(), self.relay.url().to_string()],
            vec!["qel-transports".into(), "nostr-ws".into()],
            vec!["d".into(), format!("{kind_label}:{conn_hex}")],
        ];
        let content = json!({
            "type": kind_label,
            "version": 2,
            "ecdh_public": self.pk,
            "conn": conn_hex,
        })
        .to_string();
        let ev = seal_event(&ghost, now, KIND_QEL_CANDIDATE, tags, content)
            .map_err(|e| io_err(io::ErrorKind::Other, e))?;
        self.relay
            .publish(&ev)
            .map_err(|e| io_err(io::ErrorKind::BrokenPipe, e))
    }
}

/// Publica um segmento 39406 cifrado NIP-44.
fn publish_frame(
    relay: &PersistentRelay,
    ghost: &GhostId,
    peer_pk: &str,
    stream_hex: &str,
    frame: &Frame,
) -> Result<(), io::Error> {
    let plain = base64::engine::general_purpose::STANDARD.encode(frame.encode());
    let content =
        encrypt_nip44(ghost, peer_pk, &plain).map_err(|e| io_err(io::ErrorKind::Other, e))?;
    let now = now_secs();
    let tags = vec![
        vec!["qel".into(), "data".into()],
        vec!["p".into(), peer_pk.to_string()],
        vec!["qel-stream".into(), stream_hex.to_string()],
        vec!["expiration".into(), (now + FRAME_EXPIRATION_SECS).to_string()],
        vec!["d".into(), hex::encode(random_conn_id())],
    ];
    let ev = seal_event(ghost, now, KIND_QEL_BACKCHANNEL, tags, content)
        .map_err(|e| io_err(io::ErrorKind::Other, e))?;
    relay
        .publish(&ev)
        .map_err(|e| io_err(io::ErrorKind::BrokenPipe, e))
}

fn parse_frame(sk: &[u8; 32], ev: &NostrEvent) -> Option<Frame> {
    // NIP-44 autentica: só o peer (ECDH com a nossa chave) produz um MAC válido.
    let plain = decrypt_nip44_to_string(sk, &ev.pubkey, &ev.content).ok()?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(plain.trim())
        .ok()?;
    Frame::decode(&bytes)
}

fn initial_rto() -> Duration {
    // Pelo Tor cada evento atravessa dois circuitos; começar folgado e medir.
    match mycelium_nostr::net::socks5_proxy() {
        Ok(Some(_)) => Duration::from_secs(6),
        _ => Duration::from_secs(3),
    }
}

fn earliest(times: &[Option<Instant>]) -> Option<Instant> {
    times.iter().flatten().min().copied()
}

/// Arranca o pump bidirecional: `pipe` ↔ Nostr 39406.
fn spawn_pump(
    hub: Hub,
    ghost: GhostId,
    peer_pk: String,
    id: ConnId,
    pipe: DuplexStream,
    mut rx: mpsc::UnboundedReceiver<NostrEvent>,
) {
    tokio::spawn(async move {
        let stream_hex = hex::encode(id);
        let sk = ghost.secret_key_bytes();
        let mut rel = ReliableState::new(id, initial_rto());
        let (mut pipe_r, mut pipe_w) = tokio::io::split(pipe);
        let mut pending = BytesMut::new();
        let mut read_buf = vec![0u8; MAX_PAYLOAD];
        let mut flush_at: Option<Instant> = None;
        let mut ack_at: Option<Instant> = None;
        let (mut local_eof, mut fin_sent, mut remote_fin) = (false, false, false);
        let publish = |f: &Frame| publish_frame(&hub.relay, &ghost, &peer_pk, &stream_hex, f);

        'pump: loop {
            let now = Instant::now();
            // 1. Dados (e FIN) prontos: segmentos de até MAX_PAYLOAD com ACK de carona.
            let flush_due = flush_at.is_some_and(|t| t <= now) || pending.len() >= MAX_PAYLOAD;
            if flush_due {
                while !rel.window_full() && (!pending.is_empty() || (local_eof && !fin_sent)) {
                    let chunk = pending.split_to(pending.len().min(MAX_PAYLOAD)).to_vec();
                    let fin = local_eof && pending.is_empty();
                    fin_sent |= fin;
                    if publish(&rel.push_segment(chunk, fin)).is_err() {
                        break 'pump;
                    }
                    ack_at = None;
                }
                if pending.is_empty() && (fin_sent || !local_eof) {
                    flush_at = None;
                }
            }
            // 2. ACK atrasado sem dados para ir de carona.
            if ack_at.is_some_and(|t| t <= now) {
                ack_at = None;
                if rel.ack_pending() && publish(&rel.ack_frame()).is_err() {
                    break;
                }
            }
            // 3. Retransmissão por timeout.
            match rel.on_timeout(now) {
                Ok(Some(f)) => {
                    if publish(&f).is_err() {
                        break;
                    }
                }
                Ok(None) => {}
                Err(_) => {
                    tracing::warn!(peer = %peer_pk, conn = %stream_hex, "nostr: peer não confirma — conexão encerrada");
                    break;
                }
            }
            if fin_sent && remote_fin && !rel.has_inflight() && !rel.ack_pending() {
                break;
            }

            let wake = earliest(&[
                flush_at.filter(|_| !rel.window_full()),
                ack_at,
                rel.next_deadline(),
            ]);
            tokio::select! {
                n = pipe_r.read(&mut read_buf), if !local_eof && pending.len() < SEND_BUFFER => {
                    match n {
                        Ok(0) | Err(_) => {
                            local_eof = true;
                            flush_at = Some(Instant::now());
                        }
                        Ok(n) => {
                            pending.extend_from_slice(&read_buf[..n]);
                            flush_at.get_or_insert(Instant::now() + COALESCE);
                        }
                    }
                }
                ev = rx.recv() => {
                    let Some(ev) = ev else { break };
                    if ev.pubkey != peer_pk {
                        continue;
                    }
                    let Some(frame) = parse_frame(&sk, &ev) else { continue };
                    let r = rel.on_recv(frame);
                    if !r.data.is_empty() && pipe_w.write_all(&r.data).await.is_err() {
                        break;
                    }
                    if r.fin && !remote_fin {
                        remote_fin = true;
                        let _ = pipe_w.shutdown().await;
                    }
                    if r.ack_now {
                        ack_at = Some(Instant::now());
                    } else if rel.ack_pending() {
                        ack_at.get_or_insert(Instant::now() + DELAYED_ACK);
                    }
                }
                _ = tokio::time::sleep_until(wake.unwrap_or(now)), if wake.is_some() => {}
            }
        }
        hub.unroute(&id);
        tracing::debug!(peer = %peer_pk, conn = %stream_hex, "nostr: pump terminou");
    });
}

/// Estabelece conexão Nostr (dialer): dial 39401 → handshake-ack → pump 39406.
/// `wait`: prazo para o handshake-ack.
pub(crate) async fn dial_connection(
    hub: Hub,
    peer_pk: &str,
    wait: Duration,
) -> Result<NostrConnection, io::Error> {
    let id = random_conn_id();
    let rx = hub.route(id);
    let (ack_tx, ack_rx) = oneshot::channel();
    hub.acks.lock().unwrap().insert(id, ack_tx);

    if let Err(e) = hub.publish_control(peer_pk, &id, "dial", 60) {
        hub.unroute(&id);
        return Err(e);
    }
    match tokio::time::timeout(wait, ack_rx).await {
        Ok(Ok(ack)) if ack.pubkey == peer_pk => {}
        _ => {
            hub.unroute(&id);
            tracing::warn!(peer = %peer_pk, "nostr dial: sem handshake-ack");
            return Err(io_err(io::ErrorKind::TimedOut, "nostr dial: sem handshake-ack"));
        }
    }
    tracing::info!(peer = %peer_pk, conn = %hex::encode(id), "nostr handshake OK — a abrir stream");
    let (conn, pipe) = duplex_pair();
    spawn_pump(hub.clone(), hub.ghost()?, peer_pk.to_string(), id, pipe, rx);
    Ok(conn)
}

/// Aceita um pedido de dial entrante. `None` = evento inválido/expirado.
pub(crate) fn accept_connection(
    hub: &Hub,
    dial: &NostrEvent,
) -> Result<Option<(NostrConnection, String)>, io::Error> {
    let Some(id) = tag(dial, "qel-conn").and_then(parse_conn_id) else {
        return Ok(None);
    };
    // Assinatura Schnorr + validade (`expires`).
    let mut engine = CandidateRelay {
        ghost: hub.ghost()?,
        peers: Vec::new(),
        backchannel_relay: hub.relay.url().to_string(),
        state: CandidateState::Searching,
    };
    let Some(peer) = engine.process_announcement(dial) else {
        return Ok(None);
    };
    let rx = hub.route(id);
    if let Err(e) = hub.publish_control(&peer.ghost_id, &id, "handshake-ack", 60) {
        hub.unroute(&id);
        return Err(e);
    }
    tracing::info!(peer = %peer.ghost_id, conn = %hex::encode(id), "nostr: dial aceito");
    let (conn, pipe) = duplex_pair();
    spawn_pump(hub.clone(), engine.ghost, peer.ghost_id.clone(), id, pipe, rx);
    Ok(Some((conn, peer.ghost_id)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_relay::LocalRelay;
    use std::sync::atomic::Ordering;
    use tokio_util::compat::FuturesAsyncReadCompatExt;

    const WAIT: Duration = Duration::from_secs(10);

    async fn hubs(url: &str) -> (Hub, Hub) {
        let a = GhostId::spawn_quick(600).unwrap();
        let b = GhostId::spawn_quick(600).unwrap();
        (Hub::connect(url, &a).await.unwrap(), Hub::connect(url, &b).await.unwrap())
    }

    /// Liga A→B pelo relay; devolve (conexão de A, conexão de B).
    async fn pair(a: &Hub, b: &Hub) -> (NostrConnection, NostrConnection) {
        let mut dials = b.listen();
        let b2 = b.clone();
        let acceptor = tokio::spawn(async move {
            let ev = dials.recv().await.unwrap();
            accept_connection(&b2, &ev).unwrap().unwrap().0
        });
        let ca = dial_connection(a.clone(), &b.pk, WAIT).await.unwrap();
        (ca, acceptor.await.unwrap())
    }

    #[tokio::test]
    async fn bulk_bytes_cross_in_order_with_few_events() {
        let relay = LocalRelay::spawn().await;
        let (a, b) = hubs(&relay.url).await;
        let (ca, cb) = pair(&a, &b).await;
        let (mut ca, mut cb) = (ca.compat(), cb.compat());

        // Muitas escritas pequenas: o agrupamento tem de juntá-las.
        let data: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        let sent = data.clone();
        let writer = tokio::spawn(async move {
            for chunk in sent.chunks(100) {
                ca.write_all(chunk).await.unwrap();
            }
            ca.flush().await.unwrap();
            ca
        });
        let mut got = vec![0u8; data.len()];
        tokio::time::timeout(Duration::from_secs(20), cb.read_exact(&mut got))
            .await
            .expect("bytes não chegaram")
            .unwrap();
        assert_eq!(got, data);
        let _ca = writer.await.unwrap();

        let data_events = relay.stats.accepted_of_kind(KIND_QEL_BACKCHANNEL as u64);
        // 100 KB / 16 KiB = 7 segmentos; ACKs atrasados/de carona — longe de 1000 escritas.
        assert!(data_events <= 20, "eventos de dados demais: {data_events}");
        assert_eq!(relay.stats.accepted_of_kind(KIND_QEL_CANDIDATE as u64), 2, "dial + ack, sem eco");
    }

    #[tokio::test]
    async fn simultaneous_dials_do_not_mix_streams() {
        let relay = LocalRelay::spawn().await;
        let (a, b) = hubs(&relay.url).await;
        let mut a_dials = a.listen();
        let mut b_dials = b.listen();
        let (a2, b2) = (a.clone(), b.clone());
        let acc_b = tokio::spawn(async move {
            let ev = b_dials.recv().await.unwrap();
            accept_connection(&b2, &ev).unwrap().unwrap().0
        });
        let acc_a = tokio::spawn(async move {
            let ev = a_dials.recv().await.unwrap();
            accept_connection(&a2, &ev).unwrap().unwrap().0
        });
        let (ab, ba) = tokio::join!(
            dial_connection(a.clone(), &b.pk, WAIT),
            dial_connection(b.clone(), &a.pk, WAIT)
        );
        let (mut ab, mut ba) = (ab.unwrap().compat(), ba.unwrap().compat());
        let mut at_b = acc_b.await.unwrap().compat();
        let mut at_a = acc_a.await.unwrap().compat();

        ab.write_all(b"pela conexao 1").await.unwrap();
        ba.write_all(b"pela conexao 2").await.unwrap();
        let mut buf = [0u8; 14];
        tokio::time::timeout(Duration::from_secs(10), at_b.read_exact(&mut buf)).await.unwrap().unwrap();
        assert_eq!(&buf, b"pela conexao 1");
        tokio::time::timeout(Duration::from_secs(10), at_a.read_exact(&mut buf)).await.unwrap().unwrap();
        assert_eq!(&buf, b"pela conexao 2");
    }

    #[tokio::test]
    async fn close_propagates_as_eof() {
        let relay = LocalRelay::spawn().await;
        let (a, b) = hubs(&relay.url).await;
        let (ca, cb) = pair(&a, &b).await;
        let (mut ca, mut cb) = (ca.compat(), cb.compat());
        ca.write_all(b"tchau").await.unwrap();
        ca.shutdown().await.unwrap();
        drop(ca);
        let mut all = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), cb.read_to_end(&mut all))
            .await
            .expect("EOF não chegou")
            .unwrap();
        assert_eq!(all, b"tchau");
        let routes_empty = || a.routes.lock().unwrap().is_empty();
        let deadline = Instant::now() + Duration::from_secs(5);
        drop(cb);
        while !routes_empty() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(routes_empty(), "pump de A devia terminar depois de FIN dos dois lados");
        assert!(relay.stats.events_accepted.load(Ordering::Relaxed) > 0);
    }

    #[tokio::test]
    async fn dial_without_listener_times_out_cleanly() {
        let relay = LocalRelay::spawn().await;
        let (a, b) = hubs(&relay.url).await;
        // B não escuta: nenhum ack.
        let r = dial_connection(a.clone(), &b.pk, Duration::from_millis(500)).await;
        assert!(r.is_err());
        assert!(a.routes.lock().unwrap().is_empty() && a.acks.lock().unwrap().is_empty());
    }
}
