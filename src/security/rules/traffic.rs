//! Auto-généré par le refacto architecte (rules split par catégorie).

use chrono::{Duration as ChronoDuration, Utc};
use futures_util::TryStreamExt;
use mongodb::{bson::doc, Client};
use serde_json::json;

use crate::security::{AuthEventKind, RemediationLevel, RuleContext, SecurityAlert, SecuritySeverity};
use super::helpers::{since, env_u64, env_f64, env_list, db_name, count};

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

// ---------------------------------------------------------------------------
// Rule 2 — BOUNCE_RATE_SURGE
// Hausse brutale hard bounce rate.
// Source: smtp_events | Window: 1h | Threshold: >15% OR >5x baseline
// L1 alerte, L2 throttle si >25%
// FP: listes de contacts récemment importées sans validation
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Rule 3 — SMTP_CODE_SPIKE_TEMP
// Pics codes 421/450 (refus temporaires) → indicateur de mauvaise réputation.
// Source: smtp_events | Window: 30m | Threshold: >30 occurrences
// L1 alerte
// FP: provider temporairement surchargé → corrélation avec multiples tenants
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Rule 4 — SMTP_CODE_SPIKE_PERM
// Pics codes 550/554 (refus permanents) → blacklistage ou contenu spam.
// Source: smtp_events | Window: 30m | Threshold: >20 occurrences
// L2 throttle → L3 quarantine
// FP: changement d'IP d'envoi, nouveau domaine sans réputation
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Rule 5 — NEW_DESTINATION_COUNTRY
// Nouveau pays de destination jamais vu en 30 jours pour ce tenant.
// Source: smtp_events | Window: 30d baseline vs 1h
// L1 alerte
// FP: nouveau marché légitime → acquittement manuel
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Rule 12 — QUEUE_BUILDUP
// Accumulation anormale de mails différés + retries.
// Source: smtp_events | Window: 30m | Threshold: deferred_count > 100
// L1 alerte → L2 throttle si croissant
// FP: MX destinataire down temporairement
// ---------------------------------------------------------------------------

pub async fn rule_queue_buildup(ctx: &RuleContext<'_>) -> Vec<SecurityAlert> {
    let threshold = env_u64("SEC_QUEUE_DEFERRED_THRESHOLD", 100);
    let s_30m = since(30);
    let s_1h = since(60);

    let deferred_30m = count(
        ctx.client,
        "smtp_events",
        doc! { "ts": { "$gte": &s_30m }, "status": "deferred" },
    )
    .await;
    let deferred_prev_30m = count(
        ctx.client,
        "smtp_events",
        doc! { "ts": { "$gte": &s_1h, "$lt": &s_30m }, "status": "deferred" },
    )
    .await;

    if deferred_30m < threshold {
        return vec![];
    }

    let growing = deferred_30m > deferred_prev_30m;
    let level = if growing {
        RemediationLevel::THROTTLE
    } else {
        RemediationLevel::ALERT
    };

    let mut alert = SecurityAlert::new(
        "QUEUE_BUILDUP",
        "Accumulation anormale de queue + retries",
        SecuritySeverity::Medium,
        level,
    )
    .with_signal(json!({
        "deferred_last_30m": deferred_30m,
        "deferred_prev_30m": deferred_prev_30m,
        "growing": growing,
        "threshold": threshold,
    }));

    if let Some(ref tid) = ctx.tenant_id {
        alert = alert.with_tenant(tid);
    }
    alert.stamp_audit_hash();
    vec![alert]
}

// ---------------------------------------------------------------------------
// Rule 13 — CROSS_TENANT_PAYLOAD_CORRELATION
// Même sujet/pattern sur plusieurs tenants en 1h (spam burst coordonné).
// Source: smtp_events | Window: 1h | Threshold: subject seen >3 distinct tenants
// L3 quarantine all implicated tenants
// FP: newsletters transactionnelles avec sujet commun ("Invoice #")
// ---------------------------------------------------------------------------
