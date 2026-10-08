//! Demand-driven capacity scaling decision model.
//!
//! This controller never provisions hardware or spends funds. It emits a
//! bounded recommendation from measured telemetry. Capacity is expressed in
//! EconomicEquivalents, not machine count.

use crate::{EconomyError, Result, SCHEMA_VERSION};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScaleTelemetry {
    pub paid_work_musd_per_day: f64,
    pub utilization: f64,
    pub queue_depth: u64,
    pub queue_growth_per_hour: f64,
    pub p95_latency_ms: f64,
    pub revenue_per_equivalent_musd_per_day: f64,
    pub thermal_headroom: f64,
    pub current_capacity_equivalents: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScalePolicy {
    pub high_utilization: f64,
    pub low_utilization: f64,
    pub latency_target_ms: f64,
    pub min_revenue_per_equivalent_musd_per_day: f64,
    pub min_capacity_equivalents: f64,
    pub max_capacity_equivalents: f64,
    pub scale_step_equivalents: f64,
}

impl Default for ScalePolicy {
    fn default() -> Self {
        Self {
            high_utilization: 0.80,
            low_utilization: 0.25,
            latency_target_ms: 1_000.0,
            min_revenue_per_equivalent_musd_per_day: 1.0,
            min_capacity_equivalents: 1.0,
            max_capacity_equivalents: 40.0,
            scale_step_equivalents: 1.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScaleAction {
    Hold,
    AddCapacity,
    ReduceCapacity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScaleDecision {
    pub schema_version: u32,
    pub action: ScaleAction,
    pub current_capacity_equivalents: f64,
    pub desired_capacity_equivalents: f64,
    pub utilization: f64,
    pub latency_ratio: f64,
    pub queue_pressure: bool,
    pub economics_support_scale_out: bool,
    pub thermal_pressure: bool,
    pub reason: String,
    pub automatic_provisioning: bool,
}

pub fn decide_scale(
    telemetry: &ScaleTelemetry,
    policy: &ScalePolicy,
) -> Result<ScaleDecision> {
    validate_telemetry(telemetry)?;
    validate_policy(policy)?;

    if telemetry.current_capacity_equivalents < policy.min_capacity_equivalents
        || telemetry.current_capacity_equivalents > policy.max_capacity_equivalents
    {
        return Err(EconomyError::Invalid(
            "current capacity outside scale policy bounds".into(),
        ));
    }

    let latency_ratio = telemetry.p95_latency_ms / policy.latency_target_ms;
    let queue_pressure =
        telemetry.queue_depth > 0 || telemetry.queue_growth_per_hour > 0.0;
    let economics_support_scale_out =
        telemetry.revenue_per_equivalent_musd_per_day
            >= policy.min_revenue_per_equivalent_musd_per_day;
    let thermal_pressure = telemetry.thermal_headroom < 0.25;

    let at_max = telemetry.current_capacity_equivalents
        >= policy.max_capacity_equivalents - 1e-12;
    let at_min = telemetry.current_capacity_equivalents
        <= policy.min_capacity_equivalents + 1e-12;

    let demand_pressure = telemetry.utilization >= policy.high_utilization
        && (queue_pressure || latency_ratio > 1.0);

    let (action, desired, reason) = if telemetry.paid_work_musd_per_day <= 0.0 {
        (
            ScaleAction::Hold,
            telemetry.current_capacity_equivalents,
            "no measured paid work; capacity expansion is not economically justified"
                .to_string(),
        )
    } else if demand_pressure && economics_support_scale_out && !at_max {
        let desired = (telemetry.current_capacity_equivalents
            + policy.scale_step_equivalents)
            .min(policy.max_capacity_equivalents);
        let reason = if thermal_pressure {
            "paid demand is saturating capacity and thermal pressure favors scale-out/offload"
                .to_string()
        } else {
            "paid demand, queue/latency pressure and revenue per equivalent support scale-out"
                .to_string()
        };
        (ScaleAction::AddCapacity, desired, reason)
    } else if telemetry.utilization <= policy.low_utilization
        && telemetry.queue_depth == 0
        && telemetry.queue_growth_per_hour <= 0.0
        && telemetry.revenue_per_equivalent_musd_per_day
            < policy.min_revenue_per_equivalent_musd_per_day * 0.5
        && !at_min
    {
        (
            ScaleAction::ReduceCapacity,
            (telemetry.current_capacity_equivalents
                - policy.scale_step_equivalents)
                .max(policy.min_capacity_equivalents),
            "sustained input snapshot indicates excess capacity and weak economics"
                .to_string(),
        )
    } else {
        (
            ScaleAction::Hold,
            telemetry.current_capacity_equivalents,
            if at_max && demand_pressure {
                "demand pressure exists but configured maximum capacity is reached"
                    .to_string()
            } else if demand_pressure && !economics_support_scale_out {
                "capacity is pressured but revenue per equivalent does not justify expansion"
                    .to_string()
            } else {
                "no bounded scale transition is justified by current telemetry"
                    .to_string()
            },
        )
    };

    Ok(ScaleDecision {
        schema_version: SCHEMA_VERSION,
        action,
        current_capacity_equivalents: telemetry.current_capacity_equivalents,
        desired_capacity_equivalents: desired,
        utilization: telemetry.utilization,
        latency_ratio,
        queue_pressure,
        economics_support_scale_out,
        thermal_pressure,
        reason,
        automatic_provisioning: false,
    })
}

fn validate_telemetry(t: &ScaleTelemetry) -> Result<()> {
    for (name, value) in [
        ("paid_work_musd_per_day", t.paid_work_musd_per_day),
        ("utilization", t.utilization),
        ("p95_latency_ms", t.p95_latency_ms),
        (
            "revenue_per_equivalent_musd_per_day",
            t.revenue_per_equivalent_musd_per_day,
        ),
        ("thermal_headroom", t.thermal_headroom),
        (
            "current_capacity_equivalents",
            t.current_capacity_equivalents,
        ),
    ] {
        if !value.is_finite() {
            return Err(EconomyError::Invalid(format!(
                "scale telemetry {name} must be finite"
            )));
        }
    }
    if t.paid_work_musd_per_day < 0.0
        || !(0.0..=1.0).contains(&t.utilization)
        || t.p95_latency_ms < 0.0
        || t.revenue_per_equivalent_musd_per_day < 0.0
        || !(0.0..=1.0).contains(&t.thermal_headroom)
        || t.current_capacity_equivalents <= 0.0
    {
        return Err(EconomyError::Invalid(
            "scale telemetry outside allowed bounds".into(),
        ));
    }
    if !t.queue_growth_per_hour.is_finite() {
        return Err(EconomyError::Invalid(
            "scale queue growth must be finite".into(),
        ));
    }
    Ok(())
}

fn validate_policy(p: &ScalePolicy) -> Result<()> {
    for (name, value) in [
        ("high_utilization", p.high_utilization),
        ("low_utilization", p.low_utilization),
        ("latency_target_ms", p.latency_target_ms),
        (
            "min_revenue_per_equivalent_musd_per_day",
            p.min_revenue_per_equivalent_musd_per_day,
        ),
        ("min_capacity_equivalents", p.min_capacity_equivalents),
        ("max_capacity_equivalents", p.max_capacity_equivalents),
        ("scale_step_equivalents", p.scale_step_equivalents),
    ] {
        if !value.is_finite() {
            return Err(EconomyError::Invalid(format!(
                "scale policy {name} must be finite"
            )));
        }
    }
    if !(0.0..=1.0).contains(&p.high_utilization)
        || !(0.0..=1.0).contains(&p.low_utilization)
        || p.low_utilization >= p.high_utilization
        || p.latency_target_ms <= 0.0
        || p.min_revenue_per_equivalent_musd_per_day < 0.0
        || p.min_capacity_equivalents <= 0.0
        || p.max_capacity_equivalents < p.min_capacity_equivalents
        || p.scale_step_equivalents <= 0.0
    {
        return Err(EconomyError::Invalid(
            "scale policy outside allowed bounds".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> ScaleTelemetry {
        ScaleTelemetry {
            paid_work_musd_per_day: 500.0,
            utilization: 0.50,
            queue_depth: 0,
            queue_growth_per_hour: 0.0,
            p95_latency_ms: 500.0,
            revenue_per_equivalent_musd_per_day: 5.0,
            thermal_headroom: 0.7,
            current_capacity_equivalents: 10.0,
        }
    }

    #[test]
    fn adds_capacity_only_with_paid_demand_and_economic_pressure() {
        let mut t = base();
        t.utilization = 0.90;
        t.queue_depth = 12;
        let d = decide_scale(&t, &ScalePolicy::default()).unwrap();
        assert_eq!(d.action, ScaleAction::AddCapacity);
        assert_eq!(d.desired_capacity_equivalents, 11.0);
        assert!(!d.automatic_provisioning);
    }

    #[test]
    fn zero_paid_demand_never_scales_out() {
        let mut t = base();
        t.paid_work_musd_per_day = 0.0;
        t.utilization = 0.99;
        t.queue_depth = 100;
        let d = decide_scale(&t, &ScalePolicy::default()).unwrap();
        assert_eq!(d.action, ScaleAction::Hold);
    }

    #[test]
    fn pressure_without_revenue_per_eq_holds() {
        let mut t = base();
        t.utilization = 0.95;
        t.queue_depth = 20;
        t.revenue_per_equivalent_musd_per_day = 0.2;
        let d = decide_scale(&t, &ScalePolicy::default()).unwrap();
        assert_eq!(d.action, ScaleAction::Hold);
    }

    #[test]
    fn low_use_and_weak_economics_can_recommend_reduce() {
        let mut t = base();
        t.utilization = 0.10;
        t.revenue_per_equivalent_musd_per_day = 0.2;
        let d = decide_scale(&t, &ScalePolicy::default()).unwrap();
        assert_eq!(d.action, ScaleAction::ReduceCapacity);
        assert_eq!(d.desired_capacity_equivalents, 9.0);
    }

    #[test]
    fn thermal_pressure_can_support_offload_but_not_auto_provision() {
        let mut t = base();
        t.utilization = 0.90;
        t.queue_depth = 1;
        t.thermal_headroom = 0.10;
        let d = decide_scale(&t, &ScalePolicy::default()).unwrap();
        assert_eq!(d.action, ScaleAction::AddCapacity);
        assert!(d.thermal_pressure);
        assert!(!d.automatic_provisioning);
    }
}
