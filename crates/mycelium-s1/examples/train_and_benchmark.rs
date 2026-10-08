//! Reproducible synthetic example. Its labels are illustrative, not real gameplay telemetry.
use ed25519_dalek::SigningKey;
use mycelium_s1::{
    benchmark::{self, BenchmarkConfig, Metering},
    training::{self, Dataset, TrainingConfig},
    Allowance, Ticket,
};
use serde::Serialize;
use std::{fs, path::Path};

fn save(path: &Path, value: &impl Serialize) -> Result<(), Box<dyn std::error::Error>> {
    fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/tmp/mycelium-s1-training-benchmark".into());
    let output = Path::new(&output);
    fs::create_dir_all(output)?;
    let data: Dataset = serde_json::from_str(include_str!("npc-training.json"))?;
    let config: TrainingConfig = serde_json::from_str(include_str!("training-config.json"))?;
    let (model, training_report) = training::train(&data, &config)?;
    save(&output.join("npc-trained.json"), &model)?;
    save(&output.join("training-report.json"), &training_report)?;

    let benchmark_config = BenchmarkConfig::default();
    let features = &data.validation[0].features;
    let allowed = vec![true; data.actions.len()];
    let inference = benchmark::run(&model, features, &allowed, &benchmark_config)?;
    save(&output.join("inference-benchmark.json"), &inference)?;

    // This public, deterministic key exists only for the synthetic benchmark.
    // Do not reuse this key or ticket for production licenses.
    let signing_key = SigningKey::from_bytes(&[19; 32]);
    let ticket = Ticket::issue(
        Allowance {
            id: "synthetic-benchmark-only".into(),
            studio: "example".into(),
            model: "npc-synthetic".into(),
            device: "benchmark-process".into(),
            evaluations: (benchmark_config.iterations + benchmark_config.warmup) as u64,
            expires_at: 200,
        },
        &signing_key,
    )?;
    let metered = benchmark::run_metered(
        &model,
        features,
        &allowed,
        &benchmark_config,
        Metering {
            ticket,
            key: &signing_key.verifying_key(),
            now: 100,
            model_id: "npc-synthetic",
            device: "benchmark-process",
        },
    )?;
    save(&output.join("metered-benchmark.json"), &metered)?;
    println!(
        "Synthetic held-out accuracy {:.3}; training cross-entropy {:.6} -> {:.6}",
        training_report.validation_after.as_ref().unwrap().accuracy,
        training_report.training_before.cross_entropy,
        training_report.training_after.cross_entropy
    );
    println!(
        "Inference ns median/p95/p99: {}/{}/{}; metered: {}/{}/{}; reports: {}",
        inference.median_ns,
        inference.p95_ns,
        inference.p99_ns,
        metered.median_ns,
        metered.p95_ns,
        metered.p99_ns,
        output.display()
    );
    Ok(())
}
