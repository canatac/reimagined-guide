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
