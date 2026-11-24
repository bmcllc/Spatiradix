use axum::http::StatusCode;
use axum::routing::get;
use axum::Router;
use mycelium_core::NodeId;
use singularity::{serve_horizon, EventHorizon, Orbit};
use tokio::net::TcpListener;

#[tokio::test]
async fn successful_http_responses_are_counted_but_failures_are_not() {
    // All traffic is loopback, with no external network provider or payment.
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let app = Router::new()
        .route("/ok", get(|| async { (StatusCode::OK, "delivered") }))
        .route("/bad", get(|| async { (StatusCode::INTERNAL_SERVER_ERROR, "failure") }));
    let server = tokio::spawn(async move {
        axum::serve(upstream_listener, app).await.unwrap()
    });
    let horizon = EventHorizon::shared();
    horizon.write().unwrap().expose(
        "myc.example",
        Orbit {
            ion: "habitat-app".into(),
            node: NodeId::derive(b"owned-service-node"),
            mass: 10,
            resistance: 0,
            upstream: format!("http://{upstream_addr}"),
        },
    );
    let handle = serve_horizon("127.0.0.1:0".parse().unwrap(), horizon.clone())
        .await
        .unwrap();
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let ok = client
        .get(format!("http://{}/habitat-app/ok", handle.bind))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::OK);
    assert_eq!(&ok.bytes().await.unwrap()[..], b"delivered");
    let bad = client
        .get(format!("http://{}/habitat-app/bad", handle.bind))
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let mut counters = horizon.write().unwrap();
    let before_drain = counters.delivery_snapshot("habitat-app");
    assert_eq!(before_drain.successful_responses, 1);
    assert_eq!(before_drain.body_bytes, 9);
    let delivered = counters.take_delivery_counts();
    let received = delivered.get("habitat-app").unwrap();
    assert_eq!(received.successful_responses, 1);
    assert_eq!(received.body_bytes, b"delivered".len() as u64);
    assert!(counters.take_delivery_counts().is_empty());
    let attempts = counters.take_request_counts();
    assert_eq!(attempts["habitat-app"], 2);
    drop(counters);

    handle.shutdown();
    server.abort();
}
