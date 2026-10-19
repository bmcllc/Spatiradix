//! Transporte libp2p sobre Nostr (Output bruto → upgrade Noise + Yamux no `build`).

use crate::addr::{encode_nostr_multiaddr, is_nostr_multiaddr, parse_nostr_multiaddr};
use crate::connection::{accept_connection, dial_connection, Hub, NostrConnection};
use futures::{
    channel::mpsc,
    future::{ready, Ready},
    prelude::*,
};
use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::transport::{DialOpts, ListenerId, TransportError, TransportEvent};
use libp2p::core::upgrade::Version;
use libp2p::core::Transport;
use libp2p::identity::Keypair;
use libp2p::multiaddr::Multiaddr;
use libp2p::{noise, yamux, PeerId};
use mycelium_ghostid::GhostId;
use mycelium_nostr::{seal_event, CandidateSession, KIND_QEL_CANDIDATE};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use thiserror::Error;

/// Intervalo do re-anúncio `listen:` (TTL 300 s no evento).
const REANNOUNCE: Duration = Duration::from_secs(120);

#[derive(Debug, Error)]
pub enum NostrTransportError {
    #[error("{0}")]
    Msg(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

type Incoming = (NostrConnection, Multiaddr, Multiaddr);

struct ListenerState {
    addr: Multiaddr,
    tell_new_addr: bool,
    incoming_rx: mpsc::UnboundedReceiver<Incoming>,
    _task: AbortOnDrop,
}

/// Hubs por (relay, GhostID): listener e dials partilham o WebSocket.
type Hubs = Arc<tokio::sync::Mutex<HashMap<(String, String), Hub>>>;

async fn hub_for(hubs: &Hubs, url: &str, ghost: &GhostId) -> Result<Hub, std::io::Error> {
    let key = (url.to_string(), ghost.nostr_pubkey_hex());
    let mut map = hubs.lock().await;
    if let Some(h) = map.get(&key) {
        return Ok(h.clone());
    }
    let hub = Hub::connect(url, ghost).await?;
    map.insert(key, hub.clone());
    Ok(hub)
}

/// Aborta a tarefa quando o dono é descartado.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Transporte Nostr bruto (AsyncRead/AsyncWrite).
pub struct NostrTransport {
    home: PathBuf,
    hubs: Hubs,
    listeners: HashMap<ListenerId, ListenerState>,
}

impl NostrTransport {
    pub fn new(home: PathBuf) -> Self {
        Self {
            home,
            hubs: Arc::default(),
            listeners: HashMap::new(),
        }
    }

    fn load_ghost(&self) -> Result<GhostId, NostrTransportError> {
        let (_, g) = CandidateSession::load_or_create(&self.home)
            .map_err(|e| NostrTransportError::Msg(e.to_string()))?;
        Ok(g)
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn listen_announcement(ghost: &GhostId, relay_url: &str) -> Option<mycelium_nostr::NostrEvent> {
    let now = now_secs();
    let tags = vec![
        vec!["qel".into(), "candidate-relay".into()],
        vec!["expires".into(), (now + 300).to_string()],
        vec!["qel-backchannel".into(), relay_url.to_string()],
        vec!["qel-transports".into(), "nostr-ws".into()],
        vec!["d".into(), format!("listen:{}", ghost.nostr_pubkey_hex())],
    ];
    let content = json!({
        "type": "candidate-relay",
        "version": 2,
        "ecdh_public": ghost.nostr_pubkey_hex(),
    })
    .to_string();
    seal_event(ghost, now, KIND_QEL_CANDIDATE, tags, content).ok()
}

impl Transport for NostrTransport {
    type Output = NostrConnection;
    type Error = NostrTransportError;
    type ListenerUpgrade = Ready<Result<Self::Output, Self::Error>>;
    type Dial = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    fn listen_on(
        &mut self,
        id: ListenerId,
        addr: Multiaddr,
    ) -> Result<(), TransportError<Self::Error>> {
        if !is_nostr_multiaddr(&addr) {
            return Err(TransportError::MultiaddrNotSupported(addr));
        }
        let (relay_url, _ghost_in_addr) = parse_nostr_multiaddr(&addr)
            .map_err(|e| TransportError::Other(NostrTransportError::Msg(e.to_string())))?;

        let ghost = self.load_ghost().map_err(TransportError::Other)?;
        let (tx, rx) = mpsc::unbounded::<Incoming>();
        let hubs = Arc::clone(&self.hubs);
        let addr_bg = addr.clone();

        let task = tokio::spawn(async move {
            let hub = match hub_for(&hubs, &relay_url, &ghost).await {
                Ok(h) => h,
                Err(e) => {
                    tracing::warn!(error = %e, "nostr listen connect");
                    return;
                }
            };
            let mut dials = hub.listen();

            // Re-anúncio periódico da sessão estável (TTL candidate).
            let hub_ann = hub.clone();
            let relay_ann = relay_url.clone();
            let _announcer = AbortOnDrop(tokio::spawn(async move {
                let mut tick = tokio::time::interval(REANNOUNCE);
                loop {
                    tick.tick().await;
                    let Ok(g) = hub_ann.ghost() else { continue };
                    if let Some(ann) = listen_announcement(&g, &relay_ann) {
                        if hub_ann.relay.publish(&ann).is_err() {
                            return;
                        }
                    }
                }
            }));

            // Ids já vistos: o relay repete eventos (reconexão, `since`).
            let mut seen: HashSet<String> = HashSet::new();
            while let Some(ev) = dials.recv().await {
                if !seen.insert(ev.id.clone()) {
                    continue;
                }
                if seen.len() > 4096 {
                    seen.clear();
                }
                match accept_connection(&hub, &ev) {
                    Ok(Some((conn, peer))) => {
                        let send_back = encode_nostr_multiaddr(&relay_url, &peer);
                        if tx.unbounded_send((conn, addr_bg.clone(), send_back)).is_err() {
                            break;
                        }
                    }
                    Ok(None) => tracing::debug!(id = %ev.id, "nostr: dial inválido/expirado ignorado"),
                    Err(e) => tracing::warn!(error = %e, "accept_connection"),
                }
            }
        });

        self.listeners.insert(
            id,
            ListenerState {
                addr,
                tell_new_addr: true,
                incoming_rx: rx,
                _task: AbortOnDrop(task),
            },
        );
        Ok(())
    }

    fn remove_listener(&mut self, id: ListenerId) -> bool {
        // Descartar o estado aborta a tarefa do listener (e o re-anúncio).
        self.listeners.remove(&id).is_some()
    }

    fn dial(
        &mut self,
        addr: Multiaddr,
        _opts: DialOpts,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        let (relay_url, peer_ghost) = match parse_nostr_multiaddr(&addr) {
            Ok(x) => x,
            Err(_) => return Err(TransportError::MultiaddrNotSupported(addr)),
        };
        let local = self.load_ghost().map_err(TransportError::Other)?;
        let hubs = Arc::clone(&self.hubs);
        Ok(Box::pin(async move {
            let hub = hub_for(&hubs, &relay_url, &local).await?;
            let wait = mycelium_nostr::net::proxied_timeout(Duration::from_secs(15));
            dial_connection(hub, &peer_ghost, wait)
                .await
                .map_err(NostrTransportError::from)
        }))
    }

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        let ids: Vec<ListenerId> = self.listeners.keys().copied().collect();
        for id in ids {
            let Some(listener) = self.listeners.get_mut(&id) else {
                continue;
            };
            if listener.tell_new_addr {
                listener.tell_new_addr = false;
                let listen_addr = listener.addr.clone();
                return Poll::Ready(TransportEvent::NewAddress {
                    listener_id: id,
                    listen_addr,
                });
            }
            match listener.incoming_rx.poll_next_unpin(cx) {
                Poll::Ready(Some((conn, local_addr, send_back_addr))) => {
                    return Poll::Ready(TransportEvent::Incoming {
                        listener_id: id,
                        upgrade: ready(Ok(conn)),
                        local_addr,
                        send_back_addr,
                    });
                }
                Poll::Ready(None) => {
                    self.listeners.remove(&id);
                    return Poll::Ready(TransportEvent::ListenerClosed {
                        listener_id: id,
                        reason: Ok(()),
                    });
                }
                Poll::Pending => {}
            }
        }
        Poll::Pending
    }
}

/// Transporte pronto para SwarmBuilder::with_other_transport.
pub fn build(
    keypair: &Keypair,
    home: PathBuf,
) -> Result<libp2p::core::transport::Boxed<(PeerId, StreamMuxerBox)>, String> {
    let noise = noise::Config::new(keypair).map_err(|e| e.to_string())?;
    // Sem prazo, um dial entrante cujo dono sumiu (evento antigo no relay)
    // deixaria um upgrade Noise pendurado para sempre.
    let upgrade_timeout = mycelium_nostr::net::proxied_timeout(Duration::from_secs(60));
    let transport = NostrTransport::new(home)
        .upgrade(Version::V1Lazy)
        .authenticate(noise)
        .multiplex(yamux::Config::default())
        .timeout(upgrade_timeout)
        .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)))
        .boxed();
    Ok(transport)
}

/// Multiaddr de listen para a sessão CandidateRelay em `home`.
pub fn listen_multiaddr(home: &std::path::Path, relay_url: &str) -> Result<Multiaddr, String> {
    let (_, ghost) = CandidateSession::load_or_create(home).map_err(|e| e.to_string())?;
    Ok(encode_nostr_multiaddr(relay_url, &ghost.nostr_pubkey_hex()))
}
