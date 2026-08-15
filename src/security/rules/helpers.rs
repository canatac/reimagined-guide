//! Helpers partagés par toutes les règles (crate-private).

use chrono::{Duration as ChronoDuration, Utc};
use futures_util::TryStreamExt;
use mongodb::{bson::doc, Client};

pub(crate) fn since(minutes: i64) -> String {
    (Utc::now() - ChronoDuration::minutes(minutes)).to_rfc3339()
}


pub(crate) fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}


pub(crate) fn env_f64(key: &str, default: f64) -> f64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}


pub(crate) fn env_list(key: &str) -> Vec<String> {
    std::env::var(key)
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}


pub(crate) fn db_name() -> String {
    std::env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string())
}


pub(crate) async fn count(client: &Client, coll: &str, filter: mongodb::bson::Document) -> u64 {
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
