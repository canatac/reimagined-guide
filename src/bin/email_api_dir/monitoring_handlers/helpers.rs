// helpers extracted from monitoring_handlers.rs (cycle 15)
use chrono::Utc;

// ─── Shared helpers ────────────────────────────────────────────────────────

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

pub(crate) fn default_monitoring_window() -> String {
    "15m".into()
}

pub(crate) fn default_window() -> String {
    "1h".into()
}

pub(crate) fn default_mon_page() -> u32 {
    1
}
pub(crate) fn default_mon_page_size() -> u32 {
    50
}

pub(crate) fn one() -> u32 {
    1
}
pub(crate) fn twenty() -> u32 {
