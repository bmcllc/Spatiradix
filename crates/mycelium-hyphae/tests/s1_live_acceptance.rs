use mycelium_hyphae::{HyphaEvent, HyphaeConfig, HyphaeNode};
use std::time::Duration;

#[tokio::test]
async fn s1_live_is_direct_ephemeral_and_no_dtn_fallback() {
    let mut b = HyphaeNode::germinate_with(HyphaeConfig {
        seed: Some([82u8; 32]),
        listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
        bootstrap: vec![],
        enable_mdns: false,
        ..Default::default()
    }).expect("B germina");
    let peer_b = b.peer_id();

    let b_addr = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(HyphaEvent::Rooted { address }) = b.pulse().await {
                if address.to_string().contains("/tcp/") {
                    let mut dialable = address;
                    dialable.push(libp2p::multiaddr::Protocol::P2p(peer_b));
                    break dialable;
                }
            }
        }
    }).await.expect("B enraiza");

    let mut a = HyphaeNode::germinate_with(HyphaeConfig {
        seed: Some([81u8; 32]),
        listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
        bootstrap: vec![b_addr],
        enable_mdns: false,
        ..Default::default()
    }).expect("A germina");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut connected = false;
    while tokio::time::Instant::now() < deadline && !connected {
        tokio::select! {
            ev = a.pulse() => {
                if matches!(ev, Some(HyphaEvent::Anastomosis { peer }) if peer == peer_b) {
                    connected = true;
                }
            }
            _ = b.pulse() => {}
            _ = tokio::time::sleep(Duration::from_millis(20)) => {}
        }
    }
    assert!(connected, "A precisa de ligação viva com B");

    // Aguarda propagação da subscription específica de B e tenta apenas entrega LIVE.
    let payload = br#"{"kind":"ExecutionIntentProposal","nonce":1}"#.to_vec();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    let mut sent = false;
    while tokio::time::Instant::now() < deadline && !sent {
        match a.send_s1_live(peer_b, payload.clone()) {
            Ok(true) => sent = true,
            Ok(false) => {}
            Err(e) => panic!("send_s1_live falhou: {e}"),
        }
        if !sent {
            tokio::select! {
                _ = a.pulse() => {}
                _ = b.pulse() => {}
                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
            }
        }
    }
    assert!(sent, "LIVE deve entregar somente quando B estiver inscrito");

    let received = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            tokio::select! {
                _ = a.pulse() => {}
                ev = b.pulse() => {
                    if let Some(HyphaEvent::S1LiveReceived { from, data }) = ev {
                        break (from, data);
                    }
                }
            }
        }
    }).await.expect("B recebe S1 LIVE");

    assert_eq!(received.1, payload);
    assert_ne!(received.0, peer_b);

    // Um destino sem ligação viva falha imediatamente e não é armazenado em DTN.
    let offline = HyphaeNode::germinate_with(HyphaeConfig {
        seed: Some([83u8; 32]),
        listen: vec![],
        bootstrap: vec![],
        enable_mdns: false,
        ..Default::default()
    }).expect("offline germina").peer_id();
    assert!(!a.send_s1_live(offline, b"must-not-store".to_vec()).unwrap());
}
