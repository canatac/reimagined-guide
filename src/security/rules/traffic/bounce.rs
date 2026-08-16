//! Rules bounce & SMTP code spikes.

use mongodb::bson::doc;
use serde_json::json;

use crate::security::{RemediationLevel, SecurityAlert, SecuritySeverity};
use crate::security::rules::helpers::{count, env_f64, env_u64, since, RuleContext};

pub async fn rule_bounce_rate_surge(ctx: &RuleContext<'_>) -> Vec<SecurityAlert> {
    let threshold = env_f64("SEC_BOUNCE_RATE_THRESHOLD", 0.15);
    let s = since(60);
    let total = count(ctx.client, "smtp_events", doc! { "ts": { "$gte": &s } }).await;
    if total == 0 {
        return vec![];
    }
    let bounced = count(
        ctx.client,
        "smtp_events",
        doc! { "ts": { "$gte": &s }, "status": "bounced" },
    )
    .await;

    let rate = bounced as f64 / total as f64;
    if rate < threshold {
        return vec![];
    }

    let level = if rate > 0.25 {
        RemediationLevel::THROTTLE
    } else {
        RemediationLevel::ALERT
    };

    let mut alert = SecurityAlert::new(
        "BOUNCE_RATE_SURGE",
        "Hausse bounce rate",
        SecuritySeverity::High,
        level,
    )
    .with_signal(json!({
        "bounce_rate": (rate * 1000.0).round() / 1000.0,
        "bounced": bounced,
        "total": total,
        "threshold": threshold,
    }))
    .with_duration(1800);

    if let Some(ref tid) = ctx.tenant_id {
        alert = alert.with_tenant(tid);
    }
    alert.stamp_audit_hash();
    vec![alert]
}

pub async fn rule_smtp_code_spike_temp(ctx: &RuleContext<'_>) -> Vec<SecurityAlert> {
    let threshold = env_u64("SEC_SMTP_421_THRESHOLD", 30);
    let s = since(30);
    let mut total_temp = 0u64;
    for code in [421i32, 450] {
        total_temp += count(
            ctx.client,
            "smtp_events",
            doc! { "ts": { "$gte": &s }, "smtp_code": code },
        )
        .await;
    }
    if total_temp < threshold {
        return vec![];
    }

    let mut alert = SecurityAlert::new(
        "SMTP_CODE_SPIKE_TEMP",
        "Spike codes SMTP 421/450",
        SecuritySeverity::Medium,
        RemediationLevel::ALERT,
    )
    .with_signal(json!({
        "count_30m": total_temp,
        "threshold": threshold,
        "codes": [421, 450],
    }));

    if let Some(ref tid) = ctx.tenant_id {
        alert = alert.with_tenant(tid);
    }
    alert.stamp_audit_hash();
    vec![alert]
}

pub async fn rule_smtp_code_spike_perm(ctx: &RuleContext<'_>) -> Vec<SecurityAlert> {
    let threshold = env_u64("SEC_SMTP_550_THRESHOLD", 20);
    let s = since(30);
    let mut total_perm = 0u64;
    for code in [550i32, 554] {
        total_perm += count(
            ctx.client,
            "smtp_events",
            doc! { "ts": { "$gte": &s }, "smtp_code": code },
        )
        .await;
    }
    if total_perm < threshold {
        return vec![];
    }

    let level = if total_perm > threshold * 5 {
        RemediationLevel::QUARANTINE
    } else {
        RemediationLevel::THROTTLE
    };

    let mut alert = SecurityAlert::new(
        "SMTP_CODE_SPIKE_PERM",
        "Spike codes SMTP 550/554",
        SecuritySeverity::High,
        level,
    )
    .with_signal(json!({
        "count_30m": total_perm,
        "threshold": threshold,
        "codes": [550, 554],
    }))
    .with_duration(3600);

    if let Some(ref tid) = ctx.tenant_id {
        alert = alert.with_tenant(tid);
    }
    alert.stamp_audit_hash();
    vec![alert]
}
