use mycelium_core::NodeId;
use rand::{Rng, RngCore};
use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, error};

// Simple temperature check using sysinfo crate (optional). For now stub.
async fn temperature_ok() -> bool {
    // Placeholder: always true. Replace with real sensor reading.
    true
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    info!("Mycelium bot starting");
    // Initialize node control (stubbed, assumes local socket).
    // TODO: connect to the local control plane via mycelium_node::call.
    loop {
        if !temperature_ok().await {
            error!("Temperature exceeds safe limit, pausing bot");
            sleep(Duration::from_secs(30)).await;
            continue;
        }
        // Simulate a trade: generate random amount and destination.
        let amount: u64 = rand::thread_rng().gen_range(1..100);
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let dest = NodeId::derive(&seed);
        // Here we would invoke a Mycelium API to submit a trade.
        // For now we log the action.
        info!("Executing trade: {} units to {}", amount, dest);
        // Placeholder for actual trade submission.
        // let _ = node_control.submit_trade(amount, dest).await;
        // Wait a short interval to keep CPU low.
        sleep(Duration::from_secs(5)).await;
    }
}
