//! 15 detection rules — each returns Some(SecurityAlert) when triggered.
//!
//! Rules are evaluated by the background engine every SECURITY_EVAL_INTERVAL_S
//! seconds (default 60). Each rule queries MongoDB over a configurable window.

use chrono::{Duration as ChronoDuration, Utc};
use futures_util::TryStreamExt;
use mongodb::{bson::doc, Client};
use serde_json::json;

use super::{
    AuthEventKind, RemediationLevel, SecurityAlert, SecuritySeverity,
};

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn since(minutes: i64) -> String {
    (Utc::now() - ChronoDuration::minutes(minutes)).to_rfc3339()
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_f64(key: &str, default: f64) -> f64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_list(key: &str) -> Vec<String> {
    std::env::var(key)
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn db_name() -> String {
    std::env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string())
}

async fn count(client: &Client, coll: &str, filter: mongodb::bson::Document) -> u64 {
    client
        .database(&db_name())
        .collection::<mongodb::bson::Document>(coll)
        .count_documents(filter)
        .await
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Rule context passed to every rule
// ---------------------------------------------------------------------------

pub struct RuleContext<'a> {
    pub client: &'a Client,
    /// Optional: scope evaluation to a single tenant.
    pub tenant_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Rule 1 — ABUSE_VOLUME_SPIKE
// Spike anormal du volume sortant par tenant.
// Source: smtp_events | Window: 1h vs baseline 7d/24 avg
// L2 throttle if ratio > 10x, L3 quarantine if > 50x
// FP: newsletters légitimes → whitelist via SECURITY_VOLUME_WHITELIST_TENANTS
// ---------------------------------------------------------------------------
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
pub async fn rule_new_destination_country(ctx: &RuleContext<'_>) -> Vec<SecurityAlert> {
    let s_1h = since(60);
    let s_30d = since(60 * 24 * 30);

    let coll = ctx
        .client
        .database(&db_name())
        .collection::<mongodb::bson::Document>("smtp_events");

    // Countries seen in last 1h
    let recent = coll
        .distinct("country", doc! { "ts": { "$gte": &s_1h } })
        .await
        .unwrap_or_default();

    // Countries seen in last 30d (excluding last 1h)
    let historical = coll
        .distinct(
            "country",
            doc! { "ts": { "$gte": &s_30d, "$lt": &s_1h } },
        )
        .await
        .unwrap_or_default();

    let hist_set: std::collections::HashSet<String> = historical
        .iter()
        .filter_map(|b| b.as_str().map(|s| s.to_string()))
        .collect();

    let new_countries: Vec<String> = recent
        .iter()
        .filter_map(|b| b.as_str().map(|s| s.to_string()))
        .filter(|c| c != "unknown" && c != "private" && !hist_set.contains(c))
        .collect();

    if new_countries.is_empty() {
        return vec![];
    }

    let mut alert = SecurityAlert::new(
        "NEW_DESTINATION_COUNTRY",
        "Nouveau pays de destination",
        SecuritySeverity::Medium,
        RemediationLevel::ALERT,
    )
    .with_signal(json!({
        "new_countries": new_countries,
        "historical_countries_count": hist_set.len(),
    }));

    if let Some(ref tid) = ctx.tenant_id {
        alert = alert.with_tenant(tid);
    }
    alert.stamp_audit_hash();
    vec![alert]
}

// ---------------------------------------------------------------------------
// Rule 6 — NEW_DESTINATION_ASN
// Nouveau ASN de routage MX jamais vu en 30 jours.
// Source: smtp_events | Window: 30d baseline vs 1h
// L1 alerte
// FP: routage réseau du destinataire légitime modifié
// ---------------------------------------------------------------------------
pub async fn rule_new_destination_asn(ctx: &RuleContext<'_>) -> Vec<SecurityAlert> {
    let s_1h = since(60);
    let s_30d = since(60 * 24 * 30);
    let coll = ctx
        .client
        .database(&db_name())
        .collection::<mongodb::bson::Document>("smtp_events");

    let recent = coll
        .distinct("asn", doc! { "ts": { "$gte": &s_1h } })
        .await
        .unwrap_or_default();
    let historical = coll
        .distinct("asn", doc! { "ts": { "$gte": &s_30d, "$lt": &s_1h } })
        .await
        .unwrap_or_default();

    let hist_set: std::collections::HashSet<String> = historical
        .iter()
        .filter_map(|b| b.as_str().map(|s| s.to_string()))
        .collect();

    let new_asns: Vec<String> = recent
        .iter()
        .filter_map(|b| b.as_str().map(|s| s.to_string()))
        .filter(|a| a != "unknown" && a != "private" && !hist_set.contains(a))
        .collect();

    if new_asns.is_empty() {
        return vec![];
    }

    let mut alert = SecurityAlert::new(
        "NEW_DESTINATION_ASN",
        "Nouveau ASN de routage",
        SecuritySeverity::Low,
        RemediationLevel::ALERT,
    )
    .with_signal(json!({ "new_asns": new_asns }));

    if let Some(ref tid) = ctx.tenant_id {
        alert = alert.with_tenant(tid);
    }
    alert.stamp_audit_hash();
    vec![alert]
}

// ---------------------------------------------------------------------------
// Rule 7 — AUTH_BRUTE_FORCE
// Brute force SMTP AUTH ou API login.
// Source: auth_events | Window: 5m | Threshold: >10 failures/IP
// L2 throttle → L4 block
// FP: outils d'automatisation mal configurés côté client
// ---------------------------------------------------------------------------
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
pub async fn rule_high_risk_asn_country(ctx: &RuleContext<'_>) -> Vec<SecurityAlert> {
    let risk_countries = env_list("MONITORING_FORBIDDEN_COUNTRIES");
    let risk_asns = env_list("SECURITY_FORBIDDEN_ASNS");
    if risk_countries.is_empty() && risk_asns.is_empty() {
        return vec![];
    }

    let s = since(60);
    let mut filter = doc! { "ts": { "$gte": &s } };

    let mut conditions = vec![];
    if !risk_countries.is_empty() {
        let bson_countries: Vec<_> = risk_countries
            .iter()
            .map(|c| mongodb::bson::Bson::String(c.clone()))
            .collect();
        conditions.push(doc! { "country": { "$in": bson_countries } });
    }
    if !risk_asns.is_empty() {
        let bson_asns: Vec<_> = risk_asns
            .iter()
            .map(|a| mongodb::bson::Bson::String(a.clone()))
            .collect();
        conditions.push(doc! { "asn": { "$in": bson_asns } });
    }
    if !conditions.is_empty() {
        filter.insert("$or", conditions);
    }

    let hits = count(ctx.client, "smtp_events", filter).await;
    if hits == 0 {
        return vec![];
    }

    let level = if hits > env_u64("SEC_RISK_COUNTRY_VOLUME_L2", 20) {
        RemediationLevel::THROTTLE
    } else {
        RemediationLevel::ALERT
    };

    let mut alert = SecurityAlert::new(
        "HIGH_RISK_ASN_COUNTRY",
        "Connexion depuis ASN/pays à risque",
        SecuritySeverity::High,
        level,
    )
    .with_signal(json!({
        "hits_1h": hits,
        "risk_countries": risk_countries,
        "risk_asns": risk_asns,
    }));

    if let Some(ref tid) = ctx.tenant_id {
        alert = alert.with_tenant(tid);
    }
    alert.stamp_audit_hash();
    vec![alert]
}

// ---------------------------------------------------------------------------
// Rule 9 — SPF_DKIM_DRIFT
// Dégradation SPF/DKIM/DMARC détectée dans les réponses SMTP.
// Source: smtp_events.smtp_reply | Window: 1h | Threshold: >10 fail mentions
// L1 alerte (correction DNS requise)
// FP: migration de provider, TTL DNS pas encore propagé
// ---------------------------------------------------------------------------
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

pub async fn evaluate_all(ctx: &RuleContext<'_>) -> Vec<SecurityAlert> {
    // Run rules concurrently where possible
    let (r1, r2, r3, r4, r5) = tokio::join!(
        rule_abuse_volume_spike(ctx),
        rule_bounce_rate_surge(ctx),
        rule_smtp_code_spike_temp(ctx),
        rule_smtp_code_spike_perm(ctx),
        rule_new_destination_country(ctx),
    );
    let (r6, r7, r8, r9, r10) = tokio::join!(
        rule_new_destination_asn(ctx),
        rule_auth_brute_force(ctx),
        rule_high_risk_asn_country(ctx),
        rule_spf_dkim_drift(ctx),
        rule_sender_identity_rotation(ctx),
    );
    let (r11, r12, r13, r14, r15) = tokio::join!(
        rule_hourly_anomaly(ctx),
        rule_queue_buildup(ctx),
        rule_cross_tenant_payload_correlation(ctx),
        rule_rate_limit_circumvention(ctx),
        rule_stale_api_key(ctx),
    );

    [r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15]
        .into_iter()
        .flatten()
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_env_u64_default() {
        std::env::remove_var("SEC_VOLUME_SPIKE_THRESHOLD");
        assert_eq!(env_u64("SEC_VOLUME_SPIKE_THRESHOLD", 999), 999);
    }

    #[test]
    fn test_env_u64_from_env() {
        std::env::set_var("SEC_TEST_VAL", "42");
        assert_eq!(env_u64("SEC_TEST_VAL", 0), 42);
        std::env::remove_var("SEC_TEST_VAL");
    }

    #[test]
    fn test_since_is_in_past() {
        let s = since(60);
        let dt = chrono::DateTime::parse_from_rfc3339(&s).unwrap();
        assert!(dt < chrono::Utc::now());
    }
}
