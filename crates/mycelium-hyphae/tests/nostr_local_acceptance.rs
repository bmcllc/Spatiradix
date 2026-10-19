//! Aceitação do transporte libp2p-sobre-Nostr com um relay **local**.
//!
//! Dois `HyphaeNode` só se conhecem pelo endereço Nostr (GhostID + URL do
//! relay em 127.0.0.1): nada de mDNS, bootstrap ou relay público. Exige-se
//! anastomose dos dois lados e entrega de uma mensagem gossipsub.
#![cfg(feature = "nostr-transport")]

use mycelium_hyphae::{HyphaEvent, HyphaeConfig, HyphaeNode};
use mycelium_nostr_transport::test_relay::{LocalRelay, RelayOptions};
use std::sync::atomic::Ordering;
use std::time::Duration;

fn node(seed: u8, home: &std::path::Path, relay: &str) -> HyphaeNode {
    HyphaeNode::germinate_with(HyphaeConfig {
        seed: Some([seed; 32]),
        listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
        enable_mdns: false,
        enable_relay_client: false,
        enable_nostr_transport: true,
        nostr_home: Some(home.to_path_buf()),
        nostr_relay: Some(relay.to_string()),
        ..Default::default()
    })
    .expect("germina")
}

fn ghost_of(home: &std::path::Path, relay: &str) -> String {
    let addr = mycelium_nostr_transport::listen_multiaddr(home, relay).unwrap();
    mycelium_nostr_transport::parse_nostr_multiaddr(&addr).unwrap().1
}

/// Conecta A→B pelo endereço Nostr e troca uma mensagem no tópico Lattice.
async fn connect_and_gossip(relay: &LocalRelay, mutual: bool) {
    let dir = temp_home();
    connect_and_gossip_in(relay, &dir, mutual).await;
    let _ = std::fs::remove_dir_all(&dir);
}

fn temp_home() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "myc-nostr-acc-{}-{}",
        std::process::id(),
        rand_suffix()
    ))
}

async fn connect_and_gossip_in(relay: &LocalRelay, dir: &std::path::Path, mutual: bool) {
    let (home_a, home_b) = (dir.join("a"), dir.join("b"));
    let mut b = node(91, &home_b, &relay.url);
    let mut a = node(92, &home_a, &relay.url);
    let (peer_a, peer_b) = (a.peer_id(), b.peer_id());

    a.reach_nostr(&relay.url, &ghost_of(&home_b, &relay.url))
        .expect("dial nostr");
    if mutual {
        // O que a descoberta do daemon faz: cada lado disca o outro.
        b.reach_nostr(&relay.url, &ghost_of(&home_a, &relay.url))
            .expect("dial nostr B→A");
    }

    let (mut a_sees_b, mut b_sees_a) = (false, false);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while !(a_sees_b && b_sees_a) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "sem anastomose via Nostr (A→B {a_sees_b}, B→A {b_sees_a}); relay aceitou {:?}",
            relay.stats.by_kind
        );
        tokio::select! {
            ev = a.pulse() => if matches!(ev, Some(HyphaEvent::Anastomosis { peer }) if peer == peer_b) { a_sees_b = true },
            ev = b.pulse() => if matches!(ev, Some(HyphaEvent::Anastomosis { peer }) if peer == peer_a) { b_sees_a = true },
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    }
    assert!(a.connected_neighbors() >= 1 && b.connected_neighbors() >= 1);

    // Gossipsub precisa da subscrição de B propagada até A: insistir até publicar.
    let payload = b"plot via nostr".to_vec();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut sent = false;
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "mensagem gossipsub não chegou (publicada={sent}); relay aceitou {:?}",
            relay.stats.by_kind
        );
        if !sent {
            sent = a.broadcast_lattice(payload.clone()).unwrap_or(false);
        }
        tokio::select! {
            _ = a.pulse() => {}
            ev = b.pulse() => {
                if let Some(HyphaEvent::LatticeReceived { data, .. }) = ev {
                    if data == payload {
                        break;
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
        }
    }
}

fn rand_suffix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

#[tokio::test(flavor = "multi_thread")]
async fn two_nodes_anastomose_and_gossip_over_local_relay() {
    let relay = LocalRelay::spawn().await;
    connect_and_gossip(&relay, false).await;
    eprintln!("relay: recebidos={:?} aceites={:?} por kind={:?}", relay.stats.events_received, relay.stats.events_accepted, relay.stats.by_kind);
}

#[tokio::test(flavor = "multi_thread")]
async fn simultaneous_dials_still_anastomose() {
    let relay = LocalRelay::spawn().await;
    connect_and_gossip(&relay, true).await;
    eprintln!("relay: recebidos={:?} aceites={:?} por kind={:?}", relay.stats.events_received, relay.stats.events_accepted, relay.stats.by_kind);
}

/// Relay que limita como os públicos (rajada 4, 2 eventos/s): o transporte
/// tem de recuar e reenviar sem perder a conexão.
#[tokio::test(flavor = "multi_thread")]
async fn rate_limited_relay_still_carries_the_connection() {
    let relay = LocalRelay::spawn_with(RelayOptions {
        rate_limit: Some((4, 2)),
        ..Default::default()
    })
    .await;
    connect_and_gossip(&relay, true).await;
    let limited = relay.stats.events_rate_limited.load(Ordering::Relaxed);
    let accepted = relay.stats.events_accepted.load(Ordering::Relaxed);
    eprintln!("rate-limit: recusados={limited} aceites={accepted}");
    assert!(
        limited <= accepted,
        "mais recusas ({limited}) do que eventos aceites ({accepted}): não recuou"
    );
}

/// Reinício dos dois nós com as mesmas sessões (mesmos GhostIDs): os quadros
/// da conexão anterior continuam guardados no relay e não podem contaminar a
/// nova.
#[tokio::test(flavor = "multi_thread")]
async fn restart_with_same_ghosts_ignores_old_frames() {
    let relay = LocalRelay::spawn().await;
    let dir = temp_home();
    connect_and_gossip_in(&relay, &dir, false).await;
    let before = relay.stats.events_accepted.load(Ordering::Relaxed);
    connect_and_gossip_in(&relay, &dir, false).await;
    assert!(relay.stats.events_accepted.load(Ordering::Relaxed) > before);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Caminho do daemon: ronda de descoberta numa tarefa, resultado por canal,
/// dial com desempate (só o GhostID menor disca) e anastomose.
#[tokio::test(flavor = "multi_thread")]
async fn discovery_round_in_task_dials_once_and_anastomoses() {
    let relay = LocalRelay::spawn().await;
    let dir = temp_home();
    let (home_a, home_b) = (dir.join("a"), dir.join("b"));
    let mut a = node(93, &home_a, &relay.url);
    let mut b = node(94, &home_b, &relay.url);
    let (peer_a, peer_b) = (a.peer_id(), b.peer_id());

    // Deixa os anúncios `listen:` chegarem ao relay.
    let settle = tokio::time::Instant::now() + Duration::from_millis(500);
    while tokio::time::Instant::now() < settle {
        tokio::select! {
            _ = a.pulse() => {}
            _ = b.pulse() => {}
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    }

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    a.spawn_nostr_discovery(&relay.url, tx.clone());
    b.spawn_nostr_discovery(&relay.url, tx);
    let mut dials = Vec::new();
    let (mut a_sees_b, mut b_sees_a) = (false, false);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while !(a_sees_b && b_sees_a) {
        assert!(tokio::time::Instant::now() < deadline, "sem anastomose (dials {dials:?})");
        tokio::select! {
            found = rx.recv(), if dials.len() < 2 => {
                let found = found.unwrap().expect("ronda de descoberta");
                let me = found.self_ghost.clone();
                let n = if me == ghost_of(&home_a, &relay.url) {
                    a.dial_nostr_discovered(found)
                } else {
                    b.dial_nostr_discovered(found)
                };
                dials.push((me, n));
            }
            ev = a.pulse() => if matches!(ev, Some(HyphaEvent::Anastomosis { peer }) if peer == peer_b) { a_sees_b = true },
            ev = b.pulse() => if matches!(ev, Some(HyphaEvent::Anastomosis { peer }) if peer == peer_a) { b_sees_a = true },
        }
    }
    dials.sort();
    assert_eq!(dials.iter().map(|(_, n)| n).sum::<usize>(), 1, "um só dial: {dials:?}");
    assert_eq!(dials[0].1, 1, "quem disca é o GhostID menor: {dials:?}");
    let _ = std::fs::remove_dir_all(&dir);
}
