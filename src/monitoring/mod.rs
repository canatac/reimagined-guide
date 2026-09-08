pub mod alerts;
pub mod enrichment;
pub mod parse;
pub mod storage;

pub use alerts::{ActiveAlert, AlertConfig};
pub use enrichment::GeoInfo;
pub use parse::parse_smtp_code;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use tokio::sync::broadcast;
use uuid::Uuid;

static EVENT_TX: OnceLock<broadcast::Sender<SmtpEvent>> = OnceLock::new();

/// Must be called once at startup before any SMTP send.
pub fn init_bus() -> &'static broadcast::Sender<SmtpEvent> {
    EVENT_TX.get_or_init(|| {
        let (tx, _) = broadcast::channel(2048);
        tx
    })
}

pub fn get_bus() -> Option<&'static broadcast::Sender<SmtpEvent>> {
    EVENT_TX.get()
}

/// Non-blocking emit — silent if bus not initialized or no receivers.
pub fn emit(event: SmtpEvent) {
    if let Some(tx) = EVENT_TX.get() {
        let _ = tx.send(event);
    }
}

pub fn monitoring_enabled() -> bool {
    std::env::var("SMTP_MONITORING_ENABLED")
        .map(|v| v != "false" && v != "0")
        .unwrap_or(true)
}

// ---------------------------------------------------------------------------
// Event types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SmtpEventType {
    Accepted,
    Queued,
    DnsLookup,
    MxSelected,
    SmtpConnect,
    TlsOk,
    SmtpResponse,
    Delivered,
    Deferred,
    Bounced,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SmtpStatus {
    Pending,
    Delivered,
    Deferred,
    Bounced,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum BounceType {
    Hard,
    Soft,
    Policy,
}

// ---------------------------------------------------------------------------
// Unified event model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpEvent {
    /// Internal event UUID.
    pub id: String,
    /// ISO 8601 UTC timestamp.
    pub ts: String,
    pub message_id: String,
    pub correlation_id: String,
    pub tenant_id: Option<String>,
    pub event_type: SmtpEventType,
    pub from: String,
    pub to: String,
    // Routing
    pub mx_host: Option<String>,
    pub remote_ip: Option<String>,
    pub remote_port: Option<u16>,
    // Geo / provider
    pub country: Option<String>,
    pub city: Option<String>,
    pub asn: Option<String>,
    pub company: Option<String>,
    pub datacenter: Option<String>,
    // Timing (milliseconds)
    pub dns_ms: Option<u64>,
    pub connect_ms: Option<u64>,
    pub tls_ms: Option<u64>,
    pub queue_ms: Option<u64>,
    pub total_ms: Option<u64>,
    // SMTP
    pub smtp_code: Option<u16>,
    pub smtp_reply: Option<String>,
    // Status
    pub attempt: u32,
    pub status: SmtpStatus,
    pub bounce_type: Option<BounceType>,
    pub bounce_reason: Option<String>,
    /// 0–100 security risk score.
    pub risk_score: Option<f32>,
}

impl SmtpEvent {
    pub fn new(message_id: &str, event_type: SmtpEventType, from: &str, to: &str) -> Self {
        SmtpEvent {
            id: Uuid::new_v4().to_string(),
            ts: Utc::now().to_rfc3339(),
            message_id: message_id.to_string(),
            correlation_id: message_id.to_string(),
            tenant_id: None,
            event_type,
            from: from.to_string(),
            to: to.to_string(),
            mx_host: None,
            remote_ip: None,
            remote_port: None,
            country: None,
            city: None,
            asn: None,
            company: None,
            datacenter: None,
            dns_ms: None,
            connect_ms: None,
            tls_ms: None,
            queue_ms: None,
            total_ms: None,
            smtp_code: None,
            smtp_reply: None,
            attempt: 1,
            status: SmtpStatus::Pending,
            bounce_type: None,
            bounce_reason: None,
            risk_score: None,
        }
    }

    pub fn with_geo(mut self, geo: GeoInfo) -> Self {
        self.country = Some(geo.country);
        self.city = Some(geo.city);
        self.asn = Some(geo.asn);
        self.company = Some(geo.company);
        self.datacenter = geo.datacenter;
        if let Some(ip) = geo.ip {
            if self.remote_ip.is_none() {
                self.remote_ip = Some(ip);
            }
        }
        self
    }

    /// Compute security risk score (0–100) based on routing & SMTP indicators.
    /// Relevant risks: data exfiltration via untrusted relay, policy bypass,
    /// confidential email stored on hostile infrastructure (MITRE ATT&CK T1048).
    pub fn compute_risk_score(&mut self) {
        let mut score = 0.0;
        score += country_risk(self.country.as_deref(), &forbidden_countries());
        score += company_risk(self.company.as_deref(), &risky_companies());
        score += latency_risk(self.total_ms);
        score += status_risk(&self.status);
        score += smtp_code_risk(self.smtp_code);
        self.risk_score = Some(score.min(100.0));
    }
}

fn parse_env_list_upper(key: &str) -> Vec<String> {
    std::env::var(key)
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_uppercase())
        .filter(|s| !s.is_empty())
        .collect()
}

fn parse_env_list_lower(key: &str) -> Vec<String> {
    std::env::var(key)
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

fn forbidden_countries() -> Vec<String> {
    parse_env_list_upper("MONITORING_FORBIDDEN_COUNTRIES")
}

fn risky_companies() -> Vec<String> {
    parse_env_list_lower("MONITORING_RISKY_COMPANIES")
}

fn country_risk(country: Option<&str>, forbidden: &[String]) -> f32 {
    let Some(country) = country else {
        return 0.0;
    };

    let upper = country.to_uppercase();
    let mut score = 0.0;
    if forbidden.iter().any(|item| item == &upper) {
        score += 50.0;
    }

    let high_risk = ["CN", "RU", "IR", "KP", "BY"];
    if high_risk.iter().any(|code| upper.contains(code)) && score < 40.0 {
        score += 25.0;
    }

    score
}

fn company_risk(company: Option<&str>, risky_companies: &[String]) -> f32 {
    let mut score = 0.0;
    if let Some(company) = company {
        let lower = company.to_lowercase();
        if risky_companies.iter().any(|needle| lower.contains(needle)) {
            score += 30.0;
        }
    }
    if company.map(|c| c == "unknown").unwrap_or(true) {
        score += 15.0;
    }
    score
}

fn latency_risk(total_ms: Option<u64>) -> f32 {
    match total_ms {
        Some(ms) if ms > 10_000 => 10.0,
        Some(ms) if ms > 5_000 => 5.0,
        _ => 0.0,
    }
}

fn status_risk(status: &SmtpStatus) -> f32 {
    if matches!(status, SmtpStatus::Bounced) {
        10.0
    } else {
        0.0
    }
}

fn smtp_code_risk(code: Option<u16>) -> f32 {
    match code {
        Some(550 | 554) => 15.0,
        Some(421 | 450) => 5.0,
        _ => 0.0,
    }
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
