//! Measured local inference timings. No network call or frame-time guarantee is involved.
use crate::{Bucket, Model, Ticket};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::{hint::black_box, time::Instant};

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct BenchmarkConfig {
    pub iterations: usize,
    pub warmup: usize,
}

impl Default for BenchmarkConfig {
    fn default() -> Self {
        Self {
            iterations: 10_000,
            warmup: 1_000,
        }
    }
}

#[derive(Deserialize, Serialize)]
pub struct Machine {
    pub os: String,
    pub architecture: String,
    pub cpu: String,
    pub logical_cpus: usize,
    pub optimized_build: bool,
}

#[derive(Deserialize, Serialize)]
pub struct BenchmarkReport {
    pub scope: String,
    pub config: BenchmarkConfig,
    pub machine: Machine,
    pub actions: usize,
    pub features: usize,
    pub allowed_actions: usize,
    pub scalar_type: String,
    pub median_ns: u64,
    pub p95_ns: u64,
    pub p99_ns: u64,
    pub min_ns: u64,
    pub max_ns: u64,
    pub mean_ns: f64,
    pub metered: bool,
    pub allowance_evaluations_consumed: u64,
    pub counter_persistence: String,
    pub network_requests: u64,
}

pub struct Metering<'a> {
    pub ticket: Ticket,
    pub key: &'a VerifyingKey,
    pub now: u64,
    pub model_id: &'a str,
    pub device: &'a str,
}

fn machine() -> Machine {
    let cpu = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|text| {
            text.lines().find_map(|line| {
                let (key, value) = line.split_once(':')?;
                matches!(key.trim(), "model name" | "Hardware" | "Processor")
                    .then(|| value.trim().to_string())
            })
        })
        .unwrap_or_else(|| "unavailable".into());
    Machine {
        os: std::env::consts::OS.into(),
        architecture: std::env::consts::ARCH.into(),
        cpu,
        logical_cpus: std::thread::available_parallelism().map_or(1, usize::from),
        optimized_build: !cfg!(debug_assertions),
    }
}

fn percentile(sorted: &[u64], percent: usize) -> u64 {
    // Nearest-rank percentile; ranks are 1-based.
    sorted[(sorted.len() * percent).div_ceil(100).saturating_sub(1)]
}

fn measure(
    model: &Model,
    features: &[f64],
    allowed: &[bool],
    config: &BenchmarkConfig,
    mut consume: Option<&mut dyn FnMut() -> Result<(), String>>,
) -> Result<BenchmarkReport, String> {
    if config.iterations == 0 || config.iterations > 1_000_000 || config.warmup > 1_000_000 {
        return Err(
            "benchmark requires 1..=1000000 iterations and at most 1000000 warmup calls".into(),
        );
    }
    model.evaluate(features, allowed)?;
    let metered = consume.is_some();
    let mut evaluate = || -> Result<(), String> {
        if let Some(counter) = consume.as_mut() {
            counter()?;
        }
        black_box(model.evaluate(black_box(features), black_box(allowed))?);
        Ok(())
    };
    for _ in 0..config.warmup {
        evaluate()?;
    }
    let mut times = Vec::with_capacity(config.iterations);
    for _ in 0..config.iterations {
        let start = Instant::now();
        evaluate()?;
        times.push(
            u64::try_from(start.elapsed().as_nanos()).map_err(|_| "benchmark duration overflow")?,
        );
    }
    times.sort_unstable();
    let mean_ns = times.iter().map(|time| *time as f64).sum::<f64>() / times.len() as f64;
    Ok(BenchmarkReport {
        scope: if metered {
            "Model::evaluate plus Ed25519 ticket verification and an in-memory quota counter".into()
        } else {
            "Model::evaluate including dimensions, mask validation, allocation and masked softmax"
                .into()
        },
        config: config.clone(),
        machine: machine(),
        actions: model.actions.len(),
        features: features.len(),
        allowed_actions: allowed.iter().filter(|value| **value).count(),
        scalar_type: "f64".into(),
        median_ns: percentile(&times, 50),
        p95_ns: percentile(&times, 95),
        p99_ns: percentile(&times, 99),
        min_ns: times[0],
        max_ns: times[times.len() - 1],
        mean_ns,
        metered,
        allowance_evaluations_consumed: if metered {
            (config.iterations + config.warmup) as u64
        } else {
            0
        },
        counter_persistence: if metered {
            "memory_only_benchmark".into()
        } else {
            "not_applicable".into()
        },
        network_requests: 0,
    })
}

pub fn run(
    model: &Model,
    features: &[f64],
    allowed: &[bool],
    config: &BenchmarkConfig,
) -> Result<BenchmarkReport, String> {
    measure(model, features, allowed, config, None)
}

/// A metered benchmark consumes warmup and measured evaluations from a temporary bucket.
/// Use a dedicated benchmark allowance, never a production player's ticket.
pub fn run_metered(
    model: &Model,
    features: &[f64],
    allowed: &[bool],
    config: &BenchmarkConfig,
    metering: Metering<'_>,
) -> Result<BenchmarkReport, String> {
    let required = config
        .iterations
        .checked_add(config.warmup)
        .ok_or("benchmark quota overflow")? as u64;
    if metering.ticket.allowance.evaluations < required {
        return Err("benchmark allowance must cover warmup plus measured evaluations".into());
    }
    let mut bucket = Bucket::new(metering.ticket, 0)?;
    let mut consume = || {
        bucket
            .consume(
                metering.key,
                metering.now,
                metering.model_id,
                metering.device,
            )
            .map(|_| ())
    };
    measure(model, features, allowed, config, Some(&mut consume))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Allowance;
    use ed25519_dalek::SigningKey;

    fn model() -> Model {
        Model {
            actions: vec!["a".into(), "b".into()],
            weights: vec![vec![1.0], vec![-1.0]],
            bias: vec![0.0, 0.0],
        }
    }

    #[test]
    fn percentiles_and_measured_report_are_consistent() {
        assert_eq!(percentile(&[1, 2, 3, 4], 50), 2);
        assert_eq!(percentile(&[1, 2, 3, 4], 95), 4);
        let report = run(
            &model(),
            &[0.5],
            &[true, true],
            &BenchmarkConfig {
                iterations: 40,
                warmup: 3,
            },
        )
        .unwrap();
        assert!(
            report.min_ns <= report.median_ns
                && report.median_ns <= report.p95_ns
                && report.p95_ns <= report.p99_ns
                && report.p99_ns <= report.max_ns
        );
        assert_eq!(report.network_requests, 0);
        assert!(!report.metered);
        assert_eq!(report.allowance_evaluations_consumed, 0);
        assert!(run(
            &model(),
            &[f64::NAN],
            &[true, true],
            &BenchmarkConfig::default()
        )
        .is_err());
        assert!(run(
            &model(),
            &[0.0],
            &[true, true],
            &BenchmarkConfig {
                iterations: 0,
                warmup: 0
            }
        )
        .is_err());
    }

    #[test]
    fn metered_path_accounts_for_warmup_and_rejects_bad_ticket() {
        let key = SigningKey::from_bytes(&[19; 32]);
        let ticket = Ticket::issue(
            Allowance {
                id: "benchmark-only".into(),
                studio: "test".into(),
                model: "npc".into(),
                device: "pc".into(),
                evaluations: 13,
                expires_at: 200,
            },
            &key,
        )
        .unwrap();
        let config = BenchmarkConfig {
            iterations: 10,
            warmup: 3,
        };
        let report = run_metered(
            &model(),
            &[0.5],
            &[true, true],
            &config,
            Metering {
                ticket: ticket.clone(),
                key: &key.verifying_key(),
                now: 100,
                model_id: "npc",
                device: "pc",
            },
        )
        .unwrap();
        assert!(report.metered);
        assert_eq!(report.allowance_evaluations_consumed, 13);
        assert!(run_metered(
            &model(),
            &[0.5],
            &[true, true],
            &config,
            Metering {
                ticket: ticket.clone(),
                key: &key.verifying_key(),
                now: 200,
                model_id: "npc",
                device: "pc",
            }
        )
        .is_err());
        let larger = BenchmarkConfig {
            iterations: 11,
            warmup: 3,
        };
        assert!(run_metered(
            &model(),
            &[0.5],
            &[true, true],
            &larger,
            Metering {
                ticket,
                key: &key.verifying_key(),
                now: 100,
                model_id: "npc",
                device: "pc",
            }
        )
        .is_err());
    }
}
