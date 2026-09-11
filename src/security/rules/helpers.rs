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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_env_u64_default() {
        std::env::remove_var("TEST_U64_VAR");
        assert_eq!(env_u64("TEST_U64_VAR", 42), 42);
    }

    #[test]
    fn test_env_u64_reads_value() {
        std::env::set_var("TEST_U64_VAR", "100");
        assert_eq!(env_u64("TEST_U64_VAR", 0), 100);
        std::env::remove_var("TEST_U64_VAR");
    }

    #[test]
    fn test_env_u64_invalid_falls_back() {
        std::env::set_var("TEST_U64_VAR", "abc");
        assert_eq!(env_u64("TEST_U64_VAR", 99), 99);
        std::env::remove_var("TEST_U64_VAR");
    }

    #[test]
    fn test_env_f64_default() {
        std::env::remove_var("TEST_F64_VAR");
        assert_eq!(env_f64("TEST_F64_VAR", 3.14), 3.14);
    }

    #[test]
    fn test_env_f64_reads_value() {
        std::env::set_var("TEST_F64_VAR", "2.71");
        assert_eq!(env_f64("TEST_F64_VAR", 0.0), 2.71);
        std::env::remove_var("TEST_F64_VAR");
    }

    #[test]
    fn test_env_list_empty() {
        std::env::remove_var("TEST_LIST");
        assert!(env_list("TEST_LIST").is_empty());
    }

    #[test]
    fn test_env_list_splits() {
        std::env::set_var("TEST_LIST", "a,b,c");
        assert_eq!(env_list("TEST_LIST"), vec!["a", "b", "c"]);
        std::env::remove_var("TEST_LIST");
    }

    #[test]
    fn test_db_name_default() {
        std::env::remove_var("MONGODB_DATABASE");
        assert_eq!(db_name(), "mailserver");
    }

    #[test]
    fn test_db_name_custom() {
        std::env::set_var("MONGODB_DATABASE", "custom_db");
        assert_eq!(db_name(), "custom_db");
        std::env::remove_var("MONGODB_DATABASE");
    }
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
