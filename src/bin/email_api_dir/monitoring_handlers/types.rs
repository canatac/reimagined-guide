// query types extracted from monitoring_handlers.rs (cycle 15)
use serde::Deserialize;
use super::helpers::{default_monitoring_window, default_window, default_mon_page, default_mon_page_size, one, twenty};

}

// ─── Query types ───────────────────────────────────────────────────────────

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

