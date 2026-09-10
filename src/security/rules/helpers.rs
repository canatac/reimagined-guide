//! Helpers partagés par toutes les règles (crate-private).

use chrono::{Duration as ChronoDuration, Utc};
use mongodb::Client;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_f64_default() {
        std::env::remove_var("TEST_F64_MISSING");
        assert_eq!(env_f64("TEST_F64_MISSING", 3.14), 3.14);
    }

    #[test]
    fn env_f64_from_env() {
        std::env::set_var("TEST_F64_VAL", "2.718");
        assert_eq!(env_f64("TEST_F64_VAL", 0.0), 2.718);
        std::env::remove_var("TEST_F64_VAL");
    }

    #[test]
    fn env_f64_invalid_falls_back() {
        std::env::set_var("TEST_F64_BAD", "not-a-number");
        assert_eq!(env_f64("TEST_F64_BAD", 1.5), 1.5);
        std::env::remove_var("TEST_F64_BAD");
    }

    #[test]
    fn env_list_default_empty() {
        std::env::remove_var("TEST_LIST_MISSING");
        assert!(env_list("TEST_LIST_MISSING").is_empty());
    }

    #[test]
    fn env_list_from_env() {
        std::env::set_var("TEST_LIST_VAL", "x,y,z");
        assert_eq!(env_list("TEST_LIST_VAL"), vec!["x", "y", "z"]);
        std::env::remove_var("TEST_LIST_VAL");
    }

    #[test]
    fn env_list_filters_empty_values() {
        std::env::set_var("TEST_LIST_EMPTY", "a,,b, ,c,");
        assert_eq!(env_list("TEST_LIST_EMPTY"), vec!["a", "b", "c"]);
        std::env::remove_var("TEST_LIST_EMPTY");
    }

    #[test]
    fn since_returns_past_timestamp() {
        let s = since(60);
        let dt = chrono::DateTime::parse_from_rfc3339(&s).unwrap();
        assert!(dt < chrono::Utc::now());
    }

    #[test]
    fn since_different_minutes() {
        let s5 = since(5);
        let s60 = since(60);
        let dt5 = chrono::DateTime::parse_from_rfc3339(&s5).unwrap();
        let dt60 = chrono::DateTime::parse_from_rfc3339(&s60).unwrap();
        assert!(dt60 < dt5);
    }
}

// ---------------------------------------------------------------------------
// Rule 1 — ABUSE_VOLUME_SPIKE
// Spike anormal du volume sortant par tenant.
// Source: smtp_events | Window: 1h vs baseline 7d/24 avg
// L2 throttle if ratio > 10x, L3 quarantine if > 50x
// FP: newsletters légitimes → whitelist via SECURITY_VOLUME_WHITELIST_TENANTS
// ---------------------------------------------------------------------------
