//! Modo anônimo do swarm: fail-closed por construção.
//!
//! Todos os testes usam o mesmo SOCKS5 (o proxy é fixado uma vez por
//! processo); a porta não tem ninguém escutando, então nenhum teste sai da
//! máquina.
#![cfg(feature = "nostr-transport")]

use mycelium_hyphae::{HyphaeConfig, HyphaeNode};
use std::net::SocketAddr;

fn dead_proxy() -> SocketAddr {
    "127.0.0.1:9".parse().unwrap()
}

fn anon(home: &str) -> HyphaeConfig {
    HyphaeConfig {
        seed: Some([5u8; 32]),
        nostr_home: Some(std::env::temp_dir().join(format!("myc-anon-{home}-{}", std::process::id()))),
        anonymous_socks5: Some(dead_proxy()),
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn ip_dials_never_reach_the_network() {
    // Isca: um listener TCP local. Se o modo anônimo tivesse qualquer
    // transporte IP, a discagem abaixo chegaria aqui.
    let bait = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = bait.local_addr().unwrap().port();
    let mut node = HyphaeNode::germinate_with(anon("dial")).expect("germina em modo anônimo");
    for addr in [
        format!("/ip4/127.0.0.1/tcp/{port}"),
        format!("/ip6/::1/tcp/{port}"),
        format!("/ip4/127.0.0.1/udp/{port}/quic-v1"),
        format!("/dns4/localhost/tcp/{port}"),
    ] {
        let _ = node.reach(addr.parse().unwrap());
    }
    let drive = async {
        loop {
            let _ = node.pulse().await;
        }
    };
    let accepted = tokio::select! {
        r = bait.accept() => Some(r),
        _ = drive => None,
        _ = tokio::time::sleep(std::time::Duration::from_secs(4)) => None,
    };
    assert!(accepted.is_none(), "modo anônimo abriu conexão TCP direta");
}

#[tokio::test(flavor = "multi_thread")]
async fn ip_revealing_options_are_refused() {
    let cases: Vec<(&str, HyphaeConfig)> = vec![
        ("listen", HyphaeConfig { listen: vec!["/ip4/0.0.0.0/tcp/4001".parse().unwrap()], ..anon("l") }),
        ("announce_ip", HyphaeConfig { announce_ip: Some("1.2.3.4".into()), ..anon("a") }),
        ("announce_ip6", HyphaeConfig { announce_ip6: Some("2001:db8::1".into()), ..anon("a6") }),
        ("relay server", HyphaeConfig { enable_relay_server: true, ..anon("r") }),
        ("assume_reachable", HyphaeConfig { assume_reachable: true, ..anon("ar") }),
        ("webrtc", HyphaeConfig { enable_webrtc: true, ..anon("w") }),
        ("proxy remoto", HyphaeConfig { anonymous_socks5: Some("203.0.113.9:9050".parse().unwrap()), ..anon("p") }),
    ];
    for (why, cfg) in cases {
        let res = HyphaeNode::germinate_with(cfg);
        assert!(res.is_err(), "{why} deveria ser recusado");
    }
}

#[test]
fn ws_policy_follows_the_process_proxy() {
    // Depois de fixado, o proxy não muda e toda conexão WS passa por ele.
    mycelium_nostr::net::set_socks5_proxy(dead_proxy()).unwrap();
    assert!(mycelium_nostr::net::set_socks5_proxy("127.0.0.1:1080".parse().unwrap()).is_err());
    assert_eq!(mycelium_nostr::net::socks5_proxy().unwrap(), Some(dead_proxy()));
    let rt = tokio::runtime::Runtime::new().unwrap();
    // ws:// em claro é recusado; wss:// tenta o proxy morto e falha (sem fallback direto).
    assert!(rt.block_on(mycelium_nostr::net::connect_ws("ws://relay.example.org")).is_err());
    let err = rt
        .block_on(mycelium_nostr::net::connect_ws("wss://relay.example.org"))
        .unwrap_err();
    assert!(err.contains("SOCKS5 127.0.0.1:9"), "{err}");
}

/// Controle da isca: o mesmo procedimento **sem** modo anônimo conecta.
/// Se este falhar, o teste acima não prova nada.
#[tokio::test(flavor = "multi_thread")]
async fn control_direct_node_does_reach_the_bait() {
    let bait = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = bait.local_addr().unwrap().port();
    let mut node = HyphaeNode::germinate_with(HyphaeConfig {
        seed: Some([6u8; 32]),
        listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
        enable_mdns: false,
        ..Default::default()
    })
    .unwrap();
    let _ = node.reach(format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap());
    let drive = async {
        loop {
            let _ = node.pulse().await;
        }
    };
    let accepted = tokio::select! {
        r = bait.accept() => Some(r),
        _ = drive => None,
        _ = tokio::time::sleep(std::time::Duration::from_secs(4)) => None,
    };
    assert!(accepted.is_some(), "controle: o nó direto deveria discar a isca");
}
