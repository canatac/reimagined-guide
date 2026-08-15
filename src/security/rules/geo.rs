//! Auto-généré par le refacto architecte (rules split par catégorie).

use chrono::{Duration as ChronoDuration, Utc};
use futures_util::TryStreamExt;
use mongodb::{bson::doc, Client};
use serde_json::json;

use crate::security::{AuthEventKind, RemediationLevel, SecurityAlert, SecuritySeverity};
use super::helpers::RuleContext;
use super::helpers::{since, env_u64, env_f64, env_list, db_name, count};

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
