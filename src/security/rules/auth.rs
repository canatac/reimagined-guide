//! Auto-généré par le refacto architecte (rules split par catégorie).

use chrono::{Duration as ChronoDuration, Utc};
use futures_util::TryStreamExt;
use mongodb::{bson::doc, Client};
use serde_json::json;

use crate::security::{AuthEventKind, RemediationLevel, RuleContext, SecurityAlert, SecuritySeverity};
use super::helpers::{since, env_u64, env_f64, env_list, db_name, count};

pub async fn rule_auth_brute_force(ctx: &RuleContext<'_>) -> Vec<SecurityAlert> {
    let threshold = env_u64("SEC_AUTH_FAIL_THRESHOLD", 10);
    let s = since(5);
    let coll = ctx
        .client
        .database(&db_name())
        .collection::<mongodb::bson::Document>("auth_events");

    // Group failures by IP
    let pipeline = vec![
        doc! { "$match": { "ts": { "$gte": &s }, "success": false } },
        doc! { "$group": { "_id": "$ip", "count": { "$sum": 1 } } },
        doc! { "$match": { "count": { "$gte": threshold as i64 } } },
        doc! { "$sort": { "count": -1 } },
        doc! { "$limit": 20 },
    ];

    let docs = match coll.aggregate(pipeline).await {
        Ok(c) => c.try_collect::<Vec<_>>().await.unwrap_or_default(),
        Err(_) => return vec![],
    };

    let mut alerts = Vec::new();
    for d in &docs {
        let ip = d.get_str("_id").unwrap_or("unknown");
        let count_val = d.get_i64("count").unwrap_or(0) as u64;

        let level = if count_val > threshold * 5 {
            RemediationLevel::BLOCK
        } else {
            RemediationLevel::THROTTLE
        };

        let mut alert = SecurityAlert::new(
            "AUTH_BRUTE_FORCE",
            "Brute force authentification",
            SecuritySeverity::High,
            level,
        )
        .with_signal(json!({
            "ip": ip,
            "failures_5m": count_val,
            "threshold": threshold,
        }))
        .with_duration(900); // 15 min block

        alert.ip = Some(ip.to_string());
        if let Some(ref tid) = ctx.tenant_id {
            alert = alert.with_tenant(tid);
        }
        alert.stamp_audit_hash();
        alerts.push(alert);
    }
    alerts
}

// ---------------------------------------------------------------------------
// Rule 8 — HIGH_RISK_ASN_COUNTRY
// Connexion MX depuis ASN/pays à risque non habituel.
// Source: smtp_events | Window: 1h
// L1 alerte, L2 si volume > threshold
// FP: partenaires légitimes en zones géographiques sensibles
// ---------------------------------------------------------------------------

pub async fn rule_stale_api_key(ctx: &RuleContext<'_>) -> Vec<SecurityAlert> {
    let max_age_days = env_u64("SEC_API_KEY_MAX_AGE_DAYS", 90);
    // In absence of an API key rotation table, we check auth_events for
    // sessions older than max_age without a recent key-change event.
    let s_recent = since(60 * 24 * max_age_days as i64);

    let old_sessions = count(
        ctx.client,
        "auth_events",
        doc! {
            "ts": { "$lte": &s_recent },
            "success": true,
            "kind": "api_key",
        },
    )
    .await;

    if old_sessions == 0 {
        return vec![];
    }

    let mut alert = SecurityAlert::new(
        "STALE_API_KEY",
        "API key ancienne non rotée",
        SecuritySeverity::Medium,
        RemediationLevel::ALERT,
    )
    .with_signal(json!({
        "sessions_with_old_key": old_sessions,
        "max_age_days": max_age_days,
    }));

    if let Some(ref tid) = ctx.tenant_id {
        alert = alert.with_tenant(tid);
    }
    alert.stamp_audit_hash();
    vec![alert]
}

// ---------------------------------------------------------------------------
// Rule engine: evaluate all rules
// ---------------------------------------------------------------------------

