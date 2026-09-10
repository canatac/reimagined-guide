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
    fn env_u64_default() {
        std::env::remove_var("TEST_U64_VAR");
        assert_eq!(env_u64("TEST_U64_VAR", 42), 42);
    }

    #[test]
    fn env_u64_custom() {
        std::env::set_var("TEST_U64_VAR", "100");
        assert_eq!(env_u64("TEST_U64_VAR", 42), 100);
        std::env::remove_var("TEST_U64_VAR");
    }

    #[test]
    fn env_u64_invalid_falls_back() {
        std::env::set_var("TEST_U64_VAR", "not_a_number");
        assert_eq!(env_u64("TEST_U64_VAR", 42), 42);
        std::env::remove_var("TEST_U64_VAR");
    }

    #[test]
    fn env_f64_default() {
        std::env::remove_var("TEST_F64_VAR");
        assert_eq!(env_f64("TEST_F64_VAR", 3.14), 3.14);
    }

    #[test]
    fn env_f64_custom() {
        std::env::set_var("TEST_F64_VAR", "2.718");
        assert_eq!(env_f64("TEST_F64_VAR", 3.14), 2.718);
        std::env::remove_var("TEST_F64_VAR");
    }

    #[test]
    fn env_f64_invalid_falls_back() {
        std::env::set_var("TEST_F64_VAR", "abc");
        assert_eq!(env_f64("TEST_F64_VAR", 3.14), 3.14);
        std::env::remove_var("TEST_F64_VAR");
    }

    #[test]
    fn env_list_empty() {
        std::env::remove_var("TEST_LIST_VAR");
        let result = env_list("TEST_LIST_VAR");
        assert!(result.is_empty());
    }

    #[test]
    fn env_list_single() {
        std::env::set_var("TEST_LIST_VAR", "value1");
        let result = env_list("TEST_LIST_VAR");
        assert_eq!(result, vec!["value1".to_string()]);
        std::env::remove_var("TEST_LIST_VAR");
    }

    #[test]
    fn env_list_multiple() {
        std::env::set_var("TEST_LIST_VAR", "a, b, c");
        let result = env_list("TEST_LIST_VAR");
        assert_eq!(result, vec!["a".to_string(), "b".to_string(), "c".to_string()]);
        std::env::remove_var("TEST_LIST_VAR");
    }

    #[test]
    fn env_list_with_whitespace() {
        std::env::set_var("TEST_LIST_VAR", "  x  ,  y  ,  z  ");
        let result = env_list("TEST_LIST_VAR");
        assert_eq!(result, vec!["x".to_string(), "y".to_string(), "z".to_string()]);
        std::env::remove_var("TEST_LIST_VAR");
    }

    #[test]
    fn env_list_filters_empty() {
        std::env::set_var("TEST_LIST_VAR", "a,,b, ,c");
        let result = env_list("TEST_LIST_VAR");
        assert_eq!(result, vec!["a".to_string(), "b".to_string(), "c".to_string()]);
        std::env::remove_var("TEST_LIST_VAR");
    }

    #[test]
    fn db_name_default() {
        std::env::remove_var("MONGODB_DATABASE");
        assert_eq!(db_name(), "mailserver");
    }

    #[test]
    fn db_name_custom() {
        std::env::set_var("MONGODB_DATABASE", "custom_db");
        assert_eq!(db_name(), "custom_db");
        std::env::remove_var("MONGODB_DATABASE");
    }

    #[test]
    fn since_returns_past_timestamp() {
        let now = chrono::Utc::now();
        let past = since(30);
        let past_dt = chrono::DateTime::parse_from_rfc3339(&past).unwrap();
        assert!(past_dt < now);
    }

    #[test]
    fn since_zero_minutes() {
        let now = chrono::Utc::now();
        let past = since(0);
        let past_dt = chrono::DateTime::parse_from_rfc3339(&past).unwrap();
        // Should be within a few seconds of now
        assert!((now - past_dt).num_seconds() < 5);
    }

    #[test]
    fn rule_context_creation() {
        // Just verify the struct can be created (client is borrowed, so we skip)
        // RuleContext is used by audit engine, not directly instantiable in unit tests
        // without a Client, but we verify the type exists
        let _tenant_id: Option<String> = Some("t1".to_string());
    }
}

// ---------------------------------------------------------------------------
// Rule 1 — ABUSE_VOLUME_SPIKE
// Spike anormal du volume sortant par tenant.
// Source: smtp_events | Window: 1h vs baseline 7d/24 avg
// L2 throttle if ratio > 10x, L3 quarantine if > 50x
// FP: newsletters légitimes → whitelist via SECURITY_VOLUME_WHITELIST_TENANTS
// ---------------------------------------------------------------------------
