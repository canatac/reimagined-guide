// Shared helpers and query types for monitoring_handlers submodules
// Extracted from monitoring_handlers.rs in cycle 26 (LOC split).

use chrono::Utc;
use serde::Deserialize;

pub(crate) fn parse_window(s: &str) -> chrono::Duration {
    let s = s.trim();
    if let Some(n) = s.strip_suffix('m').and_then(|n| n.parse::<i64>().ok()) {
        chrono::Duration::minutes(n)
    } else if let Some(n) = s.strip_suffix('h').and_then(|n| n.parse::<i64>().ok()) {
        chrono::Duration::hours(n)
    } else if let Some(n) = s.strip_suffix('d').and_then(|n| n.parse::<i64>().ok()) {
        chrono::Duration::days(n)
    } else {
        chrono::Duration::minutes(15)
    }
}

pub(crate) fn since_str(window: &str) -> String {
    let dur = parse_window(window);
    (Utc::now() - dur).to_rfc3339()
}

pub(crate) fn default_monitoring_window() -> String { "15m".into() }
pub(crate) fn default_window() -> String { "1h".into() }
pub(crate) fn default_mon_page() -> u32 { 1 }
pub(crate) fn default_mon_page_size() -> u32 { 50 }
pub(crate) fn one() -> u32 { 1 }
pub(crate) fn twenty() -> u32 { 20 }

#[derive(Deserialize)]
pub(crate) struct MonitoringWindowQuery {
    #[serde(default = "default_monitoring_window")]
    pub window: String,
}

#[derive(Deserialize)]
pub(crate) struct MonitoringEventsQuery {
    pub status: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub provider: Option<String>,
    pub country: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub message_id: Option<String>,
    #[serde(default = "default_mon_page")]
    pub page: u32,
    #[serde(default = "default_mon_page_size")]
    pub page_size: u32,
}

#[derive(Deserialize)]
pub(crate) struct MonitoringLiveQuery {
    pub message_id: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct AdminWindowQuery {
    #[serde(default = "default_window")]
    pub window: String,
}

#[derive(serde::Deserialize)]
pub(crate) struct SecurityAlertsQuery {
    #[serde(default = "default_window")]
    pub window: String,
    pub severity: Option<String>,
    pub tenant_id: Option<String>,
}

#[derive(serde::Deserialize)]
pub(crate) struct SecurityIncidentsQuery {
    #[serde(default = "one")]
    pub page: u32,
    #[serde(default = "twenty")]
    pub page_size: u32,
    pub tenant_id: Option<String>,
    pub severity: Option<String>,
}

pub(crate) fn env_bool(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => default,
    }
}

#[cfg(test)]
mod shared_tests {
    use super::*;

    #[test]
    fn parse_window_minutes_suffix() {
        assert_eq!(parse_window("15m"), chrono::Duration::minutes(15));
        assert_eq!(parse_window("1m"), chrono::Duration::minutes(1));
        assert_eq!(parse_window("90m"), chrono::Duration::minutes(90));
    }

    #[test]
    fn parse_window_hours_suffix() {
        assert_eq!(parse_window("1h"), chrono::Duration::hours(1));
        assert_eq!(parse_window("24h"), chrono::Duration::hours(24));
    }

    #[test]
    fn parse_window_days_suffix() {
        assert_eq!(parse_window("1d"), chrono::Duration::days(1));
        assert_eq!(parse_window("7d"), chrono::Duration::days(7));
    }

    #[test]
    fn parse_window_defaults_to_15_minutes() {
        assert_eq!(parse_window(""), chrono::Duration::minutes(15));
        assert_eq!(parse_window("invalid"), chrono::Duration::minutes(15));
        assert_eq!(parse_window("15"), chrono::Duration::minutes(15));
        assert_eq!(parse_window("15x"), chrono::Duration::minutes(15));
    }

    #[test]
    fn parse_window_handles_whitespace() {
        assert_eq!(parse_window(" 15m "), chrono::Duration::minutes(15));
        assert_eq!(parse_window("\t1h\n"), chrono::Duration::hours(1));
    }

    #[test]
    fn default_monitoring_window_is_15m() {
        assert_eq!(default_monitoring_window(), "15m");
    }

    #[test]
    fn default_window_is_1h() {
        assert_eq!(default_window(), "1h");
    }

    #[test]
    fn one_returns_1() {
        assert_eq!(one(), 1);
    }

    #[test]
    fn twenty_returns_20() {
        assert_eq!(twenty(), 20);
    }

    #[test]
    fn default_monitoring_page_is_1() {
        assert_eq!(default_mon_page(), 1);
    }

    #[test]
    fn default_monitoring_page_size_is_50() {
        assert_eq!(default_mon_page_size(), 50);
    }

    #[test]
    fn env_bool_returns_default_when_unset() {
        std::env::remove_var("TEST_VAR_XYZ");
        assert!(env_bool("TEST_VAR_XYZ", true));
        assert!(!env_bool("TEST_VAR_XYZ", false));
    }

    #[test]
    fn env_bool_reads_truthy_values() {
        std::env::set_var("TEST_VAR_XYZ", "true");
        assert!(env_bool("TEST_VAR_XYZ", false));
        std::env::set_var("TEST_VAR_XYZ", "1");
        assert!(env_bool("TEST_VAR_XYZ", false));
        std::env::set_var("TEST_VAR_XYZ", "yes");
        assert!(env_bool("TEST_VAR_XYZ", false));
        std::env::set_var("TEST_VAR_XYZ", "on");
        assert!(env_bool("TEST_VAR_XYZ", false));
        std::env::remove_var("TEST_VAR_XYZ");
    }

    #[test]
    fn env_bool_reads_falsy_values() {
        std::env::set_var("TEST_VAR_XYZ", "false");
        assert!(!env_bool("TEST_VAR_XYZ", true));
        std::env::set_var("TEST_VAR_XYZ", "0");
        assert!(!env_bool("TEST_VAR_XYZ", true));
        std::env::set_var("TEST_VAR_XYZ", "no");
        assert!(!env_bool("TEST_VAR_XYZ", true));
        std::env::set_var("TEST_VAR_XYZ", "off");
        assert!(!env_bool("TEST_VAR_XYZ", true));
        std::env::remove_var("TEST_VAR_XYZ");
    }

    #[test]
    fn env_bool_case_insensitive() {
        std::env::set_var("TEST_VAR_XYZ", "TRUE");
        assert!(env_bool("TEST_VAR_XYZ", false));
        std::env::set_var("TEST_VAR_XYZ", "Yes");
        assert!(env_bool("TEST_VAR_XYZ", false));
        std::env::remove_var("TEST_VAR_XYZ");
    }
}

pub(crate) async fn dns_txt_lookup(name: &str) -> Vec<String> {
    use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
    use trust_dns_resolver::TokioAsyncResolver;

    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
    let mut rows: Vec<String> = Vec::new();

    if let Ok(lookup) = resolver.txt_lookup(name).await {
        for txt in lookup.iter() {
            for part in txt.txt_data() {
                if let Ok(s) = std::str::from_utf8(part) {
                    rows.push(s.to_string());
                }
            }
        }
    }

    rows
}
