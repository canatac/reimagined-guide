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
    fn since_returns_rfc3339_in_past() {
        let s = since(60);
        let dt = chrono::DateTime::parse_from_rfc3339(&s).unwrap();
        assert!(dt < chrono::Utc::now());
        let sixty_mins_ago = chrono::Utc::now() - chrono::Duration::minutes(60);
        let diff = (dt - sixty_mins_ago).num_seconds().abs();
        assert!(diff <= 2);
    }

    #[test]
    fn env_u64_default_when_unset() {
        std::env::remove_var("SEC_TEST_U64");
        assert_eq!(env_u64("SEC_TEST_U64", 123), 123);
    }

    #[test]
    fn env_u64_reads_valid_value() {
        std::env::set_var("SEC_TEST_U64", "456");
        assert_eq!(env_u64("SEC_TEST_U64", 0), 456);
        std::env::remove_var("SEC_TEST_U64");
    }

    #[test]
    fn env_u64_falls_back_on_invalid() {
        std::env::set_var("SEC_TEST_U64", "not-a-number");
        assert_eq!(env_u64("SEC_TEST_U64", 789), 789);
        std::env::remove_var("SEC_TEST_U64");
    }

    #[test]
    fn env_f64_default_when_unset() {
        std::env::remove_var("SEC_TEST_F64");
        assert_eq!(env_f64("SEC_TEST_F64", 3.14), 3.14);
    }

    #[test]
    fn env_f64_reads_valid_value() {
        std::env::set_var("SEC_TEST_F64", "2.718");
        assert_eq!(env_f64("SEC_TEST_F64", 0.0), 2.718);
        std::env::remove_var("SEC_TEST_F64");
    }

    #[test]
    fn env_f64_falls_back_on_invalid() {
        std::env::set_var("SEC_TEST_F64", "nope");
        assert_eq!(env_f64("SEC_TEST_F64", 1.23), 1.23);
        std::env::remove_var("SEC_TEST_F64");
    }

    #[test]
    fn env_list_empty_when_unset() {
        std::env::remove_var("SEC_TEST_LIST");
        assert!(env_list("SEC_TEST_LIST").is_empty());
    }

    #[test]
    fn env_list_splits_and_trims() {
        std::env::set_var("SEC_TEST_LIST", " a , , b ,c ");
        assert_eq!(env_list("SEC_TEST_LIST"), vec!["a", "b", "c"]);
        std::env::remove_var("SEC_TEST_LIST");
    }

    #[test]
    fn env_list_skips_empty_entries() {
        std::env::set_var("SEC_TEST_LIST", ",,,");
        assert!(env_list("SEC_TEST_LIST").is_empty());
        std::env::remove_var("SEC_TEST_LIST");
    }

    #[test]
    fn db_name_defaults_to_mailserver() {
        std::env::remove_var("MONGODB_DATABASE");
        assert_eq!(db_name(), "mailserver");
    }

    #[test]
    fn db_name_reads_from_env() {
        std::env::set_var("MONGODB_DATABASE", "rules_test_db");
        assert_eq!(db_name(), "rules_test_db");
        std::env::remove_var("MONGODB_DATABASE");
    }
}

// ---------------------------------------------------------------------------
// Rule 1 — ABUSE_VOLUME_SPIKE
// Spike anormal du volume sortant par tenant.
// Source: smtp_events | Window: 1h vs baseline 7d/24 avg
// L2 throttle if ratio > 10x, L3 quarantine if > 50x
// FP: newsletters légitimes → whitelist via SECURITY_VOLUME_WHITELIST_TENANTS
// ---------------------------------------------------------------------------
