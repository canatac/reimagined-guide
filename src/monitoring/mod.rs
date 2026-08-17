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
        let mut score: f32 = 0.0;

        let forbidden_countries: Vec<String> =
            std::env::var("MONITORING_FORBIDDEN_COUNTRIES")
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_uppercase())
                .filter(|s| !s.is_empty())
                .collect();

        if let Some(ref c) = self.country {
            if forbidden_countries.iter().any(|f| f == &c.to_uppercase()) {
                score += 50.0;
            }
        }

        // Known mass-surveillance or high-risk jurisdictions (Five Eyes + declared hostile)
        let high_risk_countries = ["CN", "RU", "IR", "KP", "BY"];
        if let Some(ref c) = self.country {
            let cu = c.to_uppercase();
            if high_risk_countries.iter().any(|h| cu.contains(*h)) && score < 40.0 {
                score += 25.0;
            }
        }

        let risky_companies: Vec<String> =
            std::env::var("MONITORING_RISKY_COMPANIES")
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .collect();

        if let Some(ref co) = self.company {
            let col = co.to_lowercase();
            if risky_companies.iter().any(|r| col.contains(r.as_str())) {
                score += 30.0;
            }
        }

        // Unknown routing infrastructure — higher risk than named providers
        if self.company.as_deref().map(|c| c == "unknown").unwrap_or(true) {
            score += 15.0;
        }

        // High latency may indicate relay/proxy
        if let Some(ms) = self.total_ms {
            if ms > 10_000 {
                score += 10.0;
            } else if ms > 5_000 {
                score += 5.0;
            }
        }

        if matches!(self.status, SmtpStatus::Bounced) {
            score += 10.0;
        }

        if let Some(code) = self.smtp_code {
            match code {
                550 | 554 => score += 15.0,
                421 | 450 => score += 5.0,
                _ => {}
            }
        }

        self.risk_score = Some(score.min(100.0));
    }
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
