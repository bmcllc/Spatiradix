//! A descoberta CandidateRelay não pode congelar o laço do organismo.
//!
//! O relay de teste aceita o WebSocket e nunca responde (como um relay lento
//! pelo Tor): a ronda de descoberta fica pendurada até os prazos estourarem.
//! Durante esse tempo o `status` tem de responder em menos de 2 s.
#![cfg(feature = "nostr-transport")]

use mycelium_node::{call, run_daemon, DaemonOptions, Request, Response};
use mycelium_nostr_transport::test_relay::{LocalRelay, RelayOptions};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tempfile::tempdir;

#[tokio::test(flavor = "multi_thread")]
async fn status_answers_while_discovery_hangs() {
    let relay = LocalRelay::spawn_with(RelayOptions {
        blackhole: true,
        ..Default::default()
    })
    .await;
    let dir = tempdir().unwrap();
    let home = dir.path().to_path_buf();
    let sock = home.join("mycelium.sock");
    let url = relay.url.clone();
    let daemon = tokio::spawn(async move {
        run_daemon(
            home,
            DaemonOptions {
                listen: vec!["/ip4/127.0.0.1/tcp/0".into()],
                horizon_port: 0,
                no_mdns: true,
                nostr_transport: Some(true),
                nostr_relay: Some(url),
                ..Default::default()
            },
        )
        .await
    });

    // A ronda de descoberta é a que pede 39401 sem `#p` (o hub do transporte filtra por `#p`).
    let discovery_req = || {
        relay
            .stats
            .req_filters
            .lock()
            .unwrap()
            .iter()
            .any(|f| f.get("#p").is_none())
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    while !discovery_req() {
        assert!(Instant::now() < deadline, "a descoberta Nostr não arrancou");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(relay.stats.connections.load(Ordering::Relaxed) >= 1);

    // O relay nunca manda EOSE: a ronda fica ~5 s pendurada. O status responde já.
    let window = Instant::now() + Duration::from_secs(3);
    let mut answered = 0;
    while Instant::now() < window {
        let t0 = Instant::now();
        let r = tokio::time::timeout(Duration::from_secs(2), call(&sock, Request::Status)).await;
        let took = t0.elapsed();
        assert!(
            matches!(r, Ok(Ok(Response::Status(_)))),
            "status não respondeu em 2 s durante a descoberta ({took:?})"
        );
        answered += 1;
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(answered >= 5);
    let _ = call(&sock, Request::Shutdown).await;
    let _ = tokio::time::timeout(Duration::from_secs(10), daemon).await;
}
