use mycelium_node::{call, run_daemon, DaemonOptions, Request, Response};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tempfile::tempdir;

async fn wait_status(sock: &std::path::Path) -> mycelium_node::StatusReport {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while tokio::time::Instant::now() < deadline {
        if let Ok(Response::Status(s)) = call(sock, Request::Status).await {
            return *s;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("status timeout: {:?}", sock);
}

#[tokio::test]
async fn s1_live_crosses_control_sockets_without_store_forward() {
    let a = tempdir().unwrap();
    let b = tempdir().unwrap();
    let a_home = a.path().to_path_buf();
    let b_home = b.path().to_path_buf();
    let a_sock = a_home.join("mycelium.sock");
    let b_sock = b_home.join("mycelium.sock");

    let b_task = tokio::spawn({
        let home = b_home.clone();
        async move {
            run_daemon(home, DaemonOptions {
                listen: vec!["/ip4/127.0.0.1/tcp/0".into()],
                horizon_port: 0,
                no_mdns: true,
                nostr_transport: Some(false),
                ..Default::default()
            }).await
        }
    });
    let _ = wait_status(&b_sock).await;
    let listen_file = b_home.join("listen_addrs.json");
    let listen_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < listen_deadline && !listen_file.exists() {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let addrs: Vec<String> = serde_json::from_str(
        &std::fs::read_to_string(&listen_file).expect("read B listen_addrs")
    ).expect("parse B listen_addrs");
    let bootstrap = addrs.into_iter()
        .find(|x| x.contains("/tcp/") && !x.contains("/quic"))
        .expect("B tcp listen");

    let a_task = tokio::spawn({
        let home = a_home.clone();
        async move {
            run_daemon(home, DaemonOptions {
                listen: vec!["/ip4/127.0.0.1/tcp/0".into()],
                bootstrap: vec![bootstrap],
                horizon_port: 0,
                no_mdns: true,
                nostr_transport: Some(false),
                ..Default::default()
            }).await
        }
    });
    let _ = wait_status(&a_sock).await;

    let connect_deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let sa = wait_status(&a_sock).await;
        let sb = wait_status(&b_sock).await;
        if sa.neighbors >= 1 && sb.neighbors >= 1 { break; }
        assert!(tokio::time::Instant::now() < connect_deadline, "nodes did not connect");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let peer_b = wait_status(&b_sock).await.peer_id;
    let payload = "{\"kind\":\"RiskApproval\",\"intent_hash\":\"0x01\"}".to_string();
    let send_deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    let mut sent = false;
    while tokio::time::Instant::now() < send_deadline && !sent {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
        sent = matches!(
            call(&a_sock, Request::S1LiveSend {
                target: peer_b.clone(),
                payload: payload.clone(),
                expires_at_ms: now + 5_000,
            }).await,
            Ok(Response::Ok { .. })
        );
        if !sent { tokio::time::sleep(Duration::from_millis(100)).await; }
    }
    assert!(sent, "S1 LIVE send did not reach subscribed peer");

    let poll_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut got = Vec::new();
    while tokio::time::Instant::now() < poll_deadline && got.is_empty() {
        if let Response::S1LiveMessages { messages } =
            call(&b_sock, Request::S1LivePoll { limit: 16 }).await.unwrap()
        {
            got = messages;
        }
        if got.is_empty() { tokio::time::sleep(Duration::from_millis(50)).await; }
    }
    assert_eq!(got, vec![payload]);

    let _ = call(&a_sock, Request::Shutdown).await;
    let _ = call(&b_sock, Request::Shutdown).await;
    let _ = tokio::time::timeout(Duration::from_secs(3), a_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(3), b_task).await;
}
