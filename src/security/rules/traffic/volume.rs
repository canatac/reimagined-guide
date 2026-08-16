//! Rules volume/hourly — abuse volume spike & hourly anomaly.

use chrono::Utc;
use mongodb::bson::doc;
use serde_json::json;

use crate::security::{RemediationLevel, SecurityAlert, SecuritySeverity};
use crate::security::rules::helpers::{count, env_f64, env_list, since, RuleContext};

pub async fn rule_abuse_volume_spike(ctx: &RuleContext<'_>) -> Vec<SecurityAlert> {
    let threshold_ratio = env_f64("SEC_VOLUME_SPIKE_RATIO", 10.0);
    let s_1h = since(60);
    let s_7d = since(60 * 24 * 7);

    let vol_1h = count(ctx.client, "smtp_events", doc! { "ts": { "$gte": &s_1h } }).await;
    let vol_7d = count(ctx.client, "smtp_events", doc! { "ts": { "$gte": &s_7d } }).await;

    if vol_7d == 0 || vol_1h == 0 {
        return vec![];
    }

    let baseline_per_hour = vol_7d as f64 / (24.0 * 7.0);
    let ratio = vol_1h as f64 / baseline_per_hour.max(1.0);

    let whitelist = env_list("SECURITY_VOLUME_WHITELIST_TENANTS");
    if let Some(ref tid) = ctx.tenant_id {
        if whitelist.contains(tid) {
            return vec![];
        }
    }

    if ratio < threshold_ratio {
        return vec![];
    }

    let level = if ratio > 50.0 {
        RemediationLevel::QUARANTINE
    } else {
        RemediationLevel::THROTTLE
    };

    let mut alert = SecurityAlert::new(
        "ABUSE_VOLUME_SPIKE",
        "Volume sortant anormal",
        SecuritySeverity::Critical,
        level,
    )
    .with_signal(json!({
        "volume_last_1h": vol_1h,
        "baseline_per_hour": baseline_per_hour.round(),
        "ratio": (ratio * 10.0).round() / 10.0,
        "threshold_ratio": threshold_ratio,
    }))
    .with_duration(3600);

    if let Some(ref tid) = ctx.tenant_id {
        alert = alert.with_tenant(tid);
    }
    alert.stamp_audit_hash();
    vec![alert]
}

pub async fn rule_hourly_anomaly(ctx: &RuleContext<'_>) -> Vec<SecurityAlert> {
    let current_hour = Utc::now().format("%H").to_string().parse::<u32>().unwrap_or(12);
    let off_peak_hours: Vec<u32> = vec![2, 3, 4, 5];
    if !off_peak_hours.contains(&current_hour) {
        return vec![];
    }

    let threshold_multiplier = env_f64("SEC_HOURLY_ANOMALY_MULTIPLIER", 5.0);
    let s_1h = since(60);
    let s_8d = since(60 * 24 * 8);

    let vol_this_hour = count(ctx.client, "smtp_events", doc! { "ts": { "$gte": &s_1h } }).await;
    let vol_7d_same_hour = count(ctx.client, "smtp_events", doc! { "ts": { "$gte": &s_8d } }).await / 7;

    let baseline = vol_7d_same_hour.max(1) as f64;
    let ratio = vol_this_hour as f64 / baseline;

    if ratio < threshold_multiplier {
        return vec![];
    }

    let mut alert = SecurityAlert::new(
        "HOURLY_ANOMALY",
        "Envoi massif hors profil horaire",
        SecuritySeverity::High,
        RemediationLevel::THROTTLE,
    )
    .with_signal(json!({
        "current_hour_utc": current_hour,
        "volume_this_hour": vol_this_hour,
        "baseline_7d_avg": vol_7d_same_hour,
        "ratio": (ratio * 10.0).round() / 10.0,
        "threshold_ratio": threshold_multiplier,
    }))
    .with_duration(3600);

    if let Some(ref tid) = ctx.tenant_id {
        alert = alert.with_tenant(tid);
    }
    alert.stamp_audit_hash();
    vec![alert]
}
