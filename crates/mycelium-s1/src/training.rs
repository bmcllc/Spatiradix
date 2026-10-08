//! Deterministic supervised training for the same fixed-logit model used by the runtime.
//! Labels are observations supplied by the studio; this does not generate gameplay data.
use crate::Model;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Sample {
    pub features: Vec<f64>,
    pub label: String,
    /// Missing masks mean that every action was available for this observation.
    #[serde(default)]
    pub allowed: Option<Vec<bool>>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Dataset {
    pub actions: Vec<String>,
    pub feature_names: Vec<String>,
    pub samples: Vec<Sample>,
    /// Independent, held-out observations. They are never used by the optimizer.
    #[serde(default)]
    pub validation: Vec<Sample>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TrainingConfig {
    pub epochs: usize,
    pub learning_rate: f64,
    pub l2: f64,
}

impl Default for TrainingConfig {
    fn default() -> Self {
        Self {
            epochs: 1000,
            learning_rate: 0.1,
            l2: 0.0001,
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Metrics {
    pub samples: usize,
    pub cross_entropy: f64,
    pub accuracy: f64,
}

#[derive(Deserialize, Serialize)]
pub struct TrainingReport {
    pub algorithm: String,
    pub config: TrainingConfig,
    pub feature_names: Vec<String>,
    pub training_before: Metrics,
    pub training_after: Metrics,
    pub validation_before: Option<Metrics>,
    pub validation_after: Option<Metrics>,
    pub initialized_from_existing_model: bool,
}

struct Observation<'a> {
    features: &'a [f64],
    label: usize,
    allowed: Vec<bool>,
}

fn unique_names(names: &[String], description: &str) -> Result<(), String> {
    if names.is_empty() || names.len() > 4096 {
        return Err(format!("{description} must contain 1..=4096 entries"));
    }
    let mut seen = BTreeSet::new();
    for name in names {
        if name.trim().is_empty() || name.trim() != name || !seen.insert(name) {
            return Err(format!(
                "{description} must be nonempty, unique, unpadded names"
            ));
        }
    }
    Ok(())
}

fn observations<'a>(
    data: &'a Dataset,
    samples: &'a [Sample],
) -> Result<Vec<Observation<'a>>, String> {
    samples
        .iter()
        .enumerate()
        .map(|(index, sample)| {
            if sample.features.len() != data.feature_names.len()
                || !sample.features.iter().all(|x| x.is_finite())
            {
                return Err(format!(
                    "sample {index}: invalid feature dimensions or non-finite value"
                ));
            }
            let label = data
                .actions
                .iter()
                .position(|action| action == &sample.label)
                .ok_or_else(|| format!("sample {index}: unknown label {}", sample.label))?;
            let allowed = sample
                .allowed
                .clone()
                .unwrap_or_else(|| vec![true; data.actions.len()]);
            if allowed.len() != data.actions.len() || !allowed[label] {
                return Err(format!(
                    "sample {index}: invalid mask or label is unavailable"
                ));
            }
            Ok(Observation {
                features: &sample.features,
                label,
                allowed,
            })
        })
        .collect()
}

fn metrics(model: &Model, samples: &[Observation<'_>]) -> Result<Metrics, String> {
    let mut loss = 0.0;
    let mut correct = 0usize;
    for sample in samples {
        let probabilities = model.evaluate(sample.features, &sample.allowed)?;
        // Compute log-sum-exp directly: taking ln(probability) would underflow
        // for a badly misclassified observation with a very large logit gap.
        let logits: Vec<f64> = model
            .weights
            .iter()
            .zip(&model.bias)
            .map(|(weights, bias)| {
                weights
                    .iter()
                    .zip(sample.features)
                    .fold(*bias, |sum, (weight, feature)| sum + weight * feature)
            })
            .collect();
        let maximum = logits
            .iter()
            .zip(&sample.allowed)
            .filter(|(_, allowed)| **allowed)
            .map(|(logit, _)| *logit)
            .fold(f64::NEG_INFINITY, f64::max);
        let denominator: f64 = logits
            .iter()
            .zip(&sample.allowed)
            .filter(|(_, allowed)| **allowed)
            .map(|(logit, _)| (logit - maximum).exp())
            .sum();
        loss += (maximum - logits[sample.label]) + denominator.ln();
        let prediction = probabilities
            .iter()
            .enumerate()
            .filter(|(index, _)| sample.allowed[*index])
            .max_by(|(left_index, left), (right_index, right)| {
                left.total_cmp(right)
                    .then_with(|| right_index.cmp(left_index))
            })
            .map(|(index, _)| index)
            .ok_or("sample has no allowed action")?;
        correct += usize::from(prediction == sample.label);
    }
    let cross_entropy = loss / samples.len() as f64;
    if !cross_entropy.is_finite() {
        return Err("non-finite loss; normalize features or lower the learning rate".into());
    }
    Ok(Metrics {
        samples: samples.len(),
        cross_entropy,
        accuracy: correct as f64 / samples.len() as f64,
    })
}

/// Train from zero parameters with full-batch cross-entropy gradient descent.
/// Repeating the same dataset and configuration produces the same artifact.
pub fn train(data: &Dataset, config: &TrainingConfig) -> Result<(Model, TrainingReport), String> {
    fit(data, config, None)
}

/// Continue training an existing runtime artifact; its action order must match the dataset.
pub fn fine_tune(
    data: &Dataset,
    config: &TrainingConfig,
    initial: &Model,
) -> Result<(Model, TrainingReport), String> {
    fit(data, config, Some(initial))
}

fn fit(
    data: &Dataset,
    config: &TrainingConfig,
    initial: Option<&Model>,
) -> Result<(Model, TrainingReport), String> {
    unique_names(&data.actions, "actions")?;
    unique_names(&data.feature_names, "feature_names")?;
    if data.actions.len() < 2 {
        return Err("supervised training requires at least two actions".into());
    }
    if data.samples.is_empty()
        || data.samples.len() > 1_000_000
        || data.validation.len() > 1_000_000
    {
        return Err(
            "training requires 1..=1000000 samples; validation allows at most 1000000".into(),
        );
    }
    if !(1..=100_000).contains(&config.epochs)
        || !config.learning_rate.is_finite()
        || config.learning_rate <= 0.0
        || !config.l2.is_finite()
        || config.l2 < 0.0
    {
        return Err("invalid epochs, learning_rate, or l2".into());
    }
    let training = observations(data, &data.samples)?;
    let validation = observations(data, &data.validation)?;
    let mut model = initial.cloned().unwrap_or_else(|| Model {
        actions: data.actions.clone(),
        weights: vec![vec![0.0; data.feature_names.len()]; data.actions.len()],
        bias: vec![0.0; data.actions.len()],
    });
    if model.actions != data.actions {
        return Err("initial model actions must match dataset action order".into());
    }
    model.evaluate(
        &vec![0.0; data.feature_names.len()],
        &vec![true; data.actions.len()],
    )?;
    let training_before = metrics(&model, &training)?;
    let validation_before = if validation.is_empty() {
        None
    } else {
        Some(metrics(&model, &validation)?)
    };
    let inverse_count = 1.0 / training.len() as f64;
    for epoch in 0..config.epochs {
        let mut weight_gradient = vec![vec![0.0; data.feature_names.len()]; data.actions.len()];
        let mut bias_gradient = vec![0.0; data.actions.len()];
        for sample in &training {
            let probabilities = model.evaluate(sample.features, &sample.allowed)?;
            for (action, probability) in probabilities.iter().enumerate() {
                let target = if action == sample.label { 1.0 } else { 0.0 };
                let delta = probability - target;
                bias_gradient[action] += delta * inverse_count;
                for (feature, value) in sample.features.iter().enumerate() {
                    weight_gradient[action][feature] += delta * value * inverse_count;
                }
            }
        }
        for action in 0..data.actions.len() {
            model.bias[action] -= config.learning_rate * bias_gradient[action];
            for feature in 0..data.feature_names.len() {
                model.weights[action][feature] -= config.learning_rate
                    * (weight_gradient[action][feature]
                        + config.l2 * model.weights[action][feature]);
            }
        }
        if !model
            .bias
            .iter()
            .chain(model.weights.iter().flatten())
            .all(|x| x.is_finite())
        {
            return Err(format!(
                "parameter overflow at epoch {epoch}; normalize features or lower learning_rate"
            ));
        }
    }
    let training_after = metrics(&model, &training)?;
    let validation_after = if validation.is_empty() {
        None
    } else {
        Some(metrics(&model, &validation)?)
    };
    Ok((
        model,
        TrainingReport {
            algorithm: "full_batch_masked_softmax_cross_entropy".into(),
            config: config.clone(),
            feature_names: data.feature_names.clone(),
            training_before,
            training_after,
            validation_before,
            validation_after,
            initialized_from_existing_model: initial.is_some(),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binary() -> Dataset {
        Dataset {
            actions: vec!["retreat".into(), "attack".into()],
            feature_names: vec!["advantage".into()],
            samples: vec![
                Sample {
                    features: vec![-1.0],
                    label: "retreat".into(),
                    allowed: None,
                },
                Sample {
                    features: vec![1.0],
                    label: "attack".into(),
                    allowed: None,
                },
            ],
            validation: vec![
                Sample {
                    features: vec![-0.8],
                    label: "retreat".into(),
                    allowed: None,
                },
                Sample {
                    features: vec![0.8],
                    label: "attack".into(),
                    allowed: None,
                },
            ],
        }
    }

    #[test]
    fn learns_and_evaluates_held_out_observations_deterministically() {
        let data = binary();
        let (model, report) = train(&data, &TrainingConfig::default()).unwrap();
        assert!(report.training_after.cross_entropy < report.training_before.cross_entropy * 0.1);
        assert_eq!(report.training_after.accuracy, 1.0);
        assert_eq!(report.validation_after.as_ref().unwrap().accuracy, 1.0);
        let (second, _) = train(&data, &TrainingConfig::default()).unwrap();
        assert_eq!(
            serde_json::to_string(&model).unwrap(),
            serde_json::to_string(&second).unwrap()
        );
        let restored: Model =
            serde_json::from_str(&serde_json::to_string(&model).unwrap()).unwrap();
        assert!(restored.evaluate(&[-0.9], &[true, true]).unwrap()[0] > 0.95);
        let (_, resumed) = fine_tune(&data, &TrainingConfig::default(), &restored).unwrap();
        assert!(resumed.initialized_from_existing_model);
        assert!(resumed.training_after.cross_entropy < resumed.training_before.cross_entropy);
    }

    #[test]
    fn held_out_labels_never_change_parameters() {
        let data = binary();
        let (first, _) = train(&data, &TrainingConfig::default()).unwrap();
        let mut changed = data.clone();
        changed.validation[0].label = "attack".into();
        let (second, report) = train(&changed, &TrainingConfig::default()).unwrap();
        assert_eq!(
            serde_json::to_string(&first).unwrap(),
            serde_json::to_string(&second).unwrap()
        );
        assert_eq!(report.validation_after.unwrap().accuracy, 0.5);
    }

    #[test]
    fn rejects_bad_labels_masks_and_numbers() {
        let mut data = binary();
        data.samples[0].allowed = Some(vec![false, true]);
        assert!(train(&data, &TrainingConfig::default()).is_err());
        data.samples[0].allowed = Some(vec![true]);
        assert!(train(&data, &TrainingConfig::default()).is_err());
        data.samples[0].allowed = None;
        data.samples[0].label = "unknown".into();
        assert!(train(&data, &TrainingConfig::default()).is_err());
        data.samples[0].label = "retreat".into();
        data.samples[0].features[0] = f64::NAN;
        assert!(train(&data, &TrainingConfig::default()).is_err());
        let invalid = TrainingConfig {
            learning_rate: f64::INFINITY,
            ..TrainingConfig::default()
        };
        assert!(train(&binary(), &invalid).is_err());
    }

    #[test]
    fn learns_with_unavailable_actions_excluded_from_gradient() {
        let mut data = binary();
        data.actions.push("help".into());
        for sample in data.samples.iter_mut().chain(&mut data.validation) {
            sample.allowed = Some(vec![true, true, false]);
        }
        let (model, report) = train(&data, &TrainingConfig::default()).unwrap();
        assert_eq!(report.training_after.accuracy, 1.0);
        assert_eq!(model.weights[2], vec![0.0]);
        assert_eq!(model.bias[2], 0.0);
        assert_eq!(
            model.evaluate(&[0.8], &[true, true, false]).unwrap()[2],
            0.0
        );
    }

    #[test]
    fn rejects_incompatible_schema_and_initial_artifacts() {
        let mut data = binary();
        data.samples[0].features.clear();
        assert!(train(&data, &TrainingConfig::default()).is_err());
        data = binary();
        data.feature_names.push("advantage".into());
        assert!(train(&data, &TrainingConfig::default()).is_err());
        data = binary();
        data.actions[1] = "retreat".into();
        assert!(train(&data, &TrainingConfig::default()).is_err());
        data = binary();
        data.samples.clear();
        assert!(train(&data, &TrainingConfig::default()).is_err());

        let data = binary();
        let (mut initial, _) = train(&data, &TrainingConfig::default()).unwrap();
        initial.actions.swap(0, 1);
        assert!(fine_tune(&data, &TrainingConfig::default(), &initial).is_err());
        initial.actions.swap(0, 1);
        initial.weights[0].push(0.0);
        assert!(fine_tune(&data, &TrainingConfig::default(), &initial).is_err());
    }
}
