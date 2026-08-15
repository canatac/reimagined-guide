//! Auto-généré par le refacto architecte (rules split par catégorie).

use chrono::{Duration as ChronoDuration, Utc};
use futures_util::TryStreamExt;
use mongodb::{bson::doc, Client};
use serde_json::json;

use crate::security::{AuthEventKind, RemediationLevel, RuleContext, SecurityAlert, SecuritySeverity};
use super::helpers::{since, env_u64, env_f64, env_list, db_name, count};

pub async fn rule_spf_dkim_drift(ctx: &RuleContext<'_>) -> Vec<SecurityAlert> {
    let threshold = env_u64("SEC_DKIM_FAIL_THRESHOLD", 10);
    let s = since(60);

    let mut total_fails = 0u64;
    for keyword in ["dkim=fail", "spf=fail", "dmarc=fail", "DMARC policy"] {
        total_fails += count(
            ctx.client,
            "smtp_events",
            doc! {
                "ts": { "$gte": &s },
                "smtp_reply": { "$regex": keyword, "$options": "i" },
            },
        )
        .await;
    }

    if total_fails < threshold {
        return vec![];
    }

    let mut alert = SecurityAlert::new(
        "SPF_DKIM_DRIFT",
        "Dégradation SPF/DKIM/DMARC",
        SecuritySeverity::High,
        RemediationLevel::ALERT,
    )
    .with_signal(json!({
        "fail_mentions_1h": total_fails,
        "threshold": threshold,
        "checked_patterns": ["dkim=fail", "spf=fail", "dmarc=fail", "DMARC policy"],
    }));

    if let Some(ref tid) = ctx.tenant_id {
        alert = alert.with_tenant(tid);
    }
    alert.stamp_audit_hash();
    vec![alert]
}

// ---------------------------------------------------------------------------
// Rule 10 — SENDER_IDENTITY_ROTATION
// Rotation rapide des adresses expéditrices (indicateur de spam burst).
// Source: smtp_events | Window: 15m | Threshold: >50 distinct from addresses
// L2 throttle
// FP: marketing tool avec alias dynamiques
// ---------------------------------------------------------------------------

pub async fn rule_sender_identity_rotation(ctx: &RuleContext<'_>) -> Vec<SecurityAlert> {
    let threshold = env_u64("SEC_SENDER_ROTATION_THRESHOLD", 50) as usize;
    let s = since(15);
    let coll = ctx
        .client
        .database(&db_name())
        .collection::<mongodb::bson::Document>("smtp_events");

    let distinct_senders = coll
        .distinct("from", doc! { "ts": { "$gte": &s } })
        .await
        .unwrap_or_default();

    if distinct_senders.len() < threshold {
        return vec![];
    }

    let mut alert = SecurityAlert::new(
        "SENDER_IDENTITY_ROTATION",
        "Rotation rapide identités expéditrices",
        SecuritySeverity::High,
        RemediationLevel::THROTTLE,
    )
    .with_signal(json!({
        "distinct_senders_15m": distinct_senders.len(),
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
// Rule 11 — HOURLY_ANOMALY
// Envoi massif hors profil horaire (2h–5h du matin UTC).
// Source: smtp_events | Window: current hour vs same-hour 7d avg
// L2 throttle
// FP: clients en timezones éloignées → whitelist timezone-aware
// ---------------------------------------------------------------------------

pub async fn rule_cross_tenant_payload_correlation(ctx: &RuleContext<'_>) -> Vec<SecurityAlert> {
    // Only run at global scope (no tenant filter)
    if ctx.tenant_id.is_some() {
        return vec![];
    }

    let s = since(60);
    let coll = ctx
        .client
        .database(&db_name())
        .collection::<mongodb::bson::Document>("smtp_events");

    let pipeline = vec![
        doc! { "$match": { "ts": { "$gte": &s } } },
        doc! { "$group": {
            "_id": "$subject",
            "tenant_count": { "$addToSet": "$tenant_id" },
            "total": { "$sum": 1 },
        }},
        doc! { "$project": {
            "subject": "$_id",
            "tenant_count": { "$size": "$tenant_count" },
            "total": 1,
        }},
        doc! { "$match": { "tenant_count": { "$gte": 3i32 } } },
        doc! { "$sort": { "tenant_count": -1 } },
        doc! { "$limit": 10 },
    ];

    let docs = match coll.aggregate(pipeline).await {
        Ok(c) => c.try_collect::<Vec<_>>().await.unwrap_or_default(),
        Err(_) => return vec![],
    };

    if docs.is_empty() {
        return vec![];
    }

    let patterns: Vec<serde_json::Value> = docs
        .iter()
        .map(|d| {
            json!({
                "subject": d.get_str("subject").unwrap_or(""),
                "tenant_count": d.get_i64("tenant_count").unwrap_or(0),
                "total_sends": d.get_i64("total").unwrap_or(0),
            })
        })
        .collect();

    let mut alert = SecurityAlert::new(
        "CROSS_TENANT_PAYLOAD_CORRELATION",
        "Payload coordonné multi-tenants",
        SecuritySeverity::Critical,
        RemediationLevel::QUARANTINE,
    )
    .with_signal(json!({ "correlated_patterns": patterns }))
    .with_duration(3600);

    alert.stamp_audit_hash();
    vec![alert]
}

// ---------------------------------------------------------------------------
// Rule 14 — RATE_LIMIT_CIRCUMVENTION
// Tentative de contournement des quotas (burst sur fenêtre glissante).
// Source: smtp_events | Window: 5m | Threshold: >quota_5min
// L2 throttle, L3 quarantine si récidive
// FP: envoi burst légitime après batch job
// ---------------------------------------------------------------------------

pub async fn rule_rate_limit_circumvention(ctx: &RuleContext<'_>) -> Vec<SecurityAlert> {
    let quota_5m = env_u64("SEC_QUOTA_5M", 500);
    let s = since(5);
    let vol = count(ctx.client, "smtp_events", doc! { "ts": { "$gte": &s } }).await;

    if vol <= quota_5m {
        return vec![];
    }

    let s_prev = since(10);
    let vol_prev = count(
        ctx.client,
        "smtp_events",
        doc! { "ts": { "$gte": &s_prev, "$lt": &s } },
    )
    .await;

    // Récidive si également dépassement sur la fenêtre précédente
    let level = if vol_prev > quota_5m {
        RemediationLevel::QUARANTINE
    } else {
        RemediationLevel::THROTTLE
    };

    let mut alert = SecurityAlert::new(
        "RATE_LIMIT_CIRCUMVENTION",
        "Contournement quota/rate limit",
        SecuritySeverity::High,
        level,
    )
    .with_signal(json!({
        "volume_5m": vol,
        "volume_prev_5m": vol_prev,
        "quota_5m": quota_5m,
        "recidive": vol_prev > quota_5m,
    }))
    .with_duration(600);

    if let Some(ref tid) = ctx.tenant_id {
        alert = alert.with_tenant(tid);
    }
    alert.stamp_audit_hash();
    vec![alert]
}

// ---------------------------------------------------------------------------
// Rule 15 — STALE_API_KEY
// Utilisation d'API key ancienne non rotée (>90j sans rotation).
// Source: users collection + auth_events | Threshold: key_age_days > 90
// L1 alerte (recommandation de rotation)
// FP: comptes de service avec longue durée de vie intentionnelle
// ---------------------------------------------------------------------------
