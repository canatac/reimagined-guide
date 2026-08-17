//! Alert engine: config, active-alert model and orchestrator.
//!
//! Individual rule checks live in [`rules`]; env parsing in [`env`].

use chrono::{Duration as ChronoDuration, Utc};
use mongodb::Client;
use serde::{Deserialize, Serialize};

mod env;
mod rules;

use env::{env_f32, env_list, env_u64};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    /// Fraction 0–1 (e.g. 0.1 = 10%).
    pub bounce_rate_threshold: f32,
    /// Milliseconds.
    pub p95_total_ms_threshold: u64,
    /// Number of errors in the window before alerting.
    pub smtp_spike_threshold: u64,
    pub forbidden_countries: Vec<String>,
    pub forbidden_companies: Vec<String>,
    /// Fraction 0–1: (sent - delivered) / sent above which we alert for silent delivery failures.
    pub undelivered_ratio_threshold: f32,
}

impl Default for AlertConfig {
    fn default() -> Self {
        AlertConfig {
            bounce_rate_threshold: env_f32("MONITORING_BOUNCE_RATE_THRESHOLD", 0.1),
            p95_total_ms_threshold: env_u64("MONITORING_P95_MS_THRESHOLD", 10_000),
            smtp_spike_threshold: env_u64("MONITORING_SMTP_SPIKE_THRESHOLD", 10),
            forbidden_countries: env_list("MONITORING_FORBIDDEN_COUNTRIES"),
            forbidden_companies: env_list("MONITORING_RISKY_COMPANIES"),
            undelivered_ratio_threshold: env_f32("MONITORING_UNDELIVERED_RATIO_THRESHOLD", 0.1),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveAlert {
    pub kind: String,
    pub severity: String,
    pub message: String,
    pub value: serde_json::Value,
    pub threshold: serde_json::Value,
    pub ts: String,
}

/// Contexte partagé pour chaque règle : accès mongo + fenêtre.
pub(crate) struct AlertCtx<'a> {
    pub client: &'a Client,
    pub db: String,
    pub since_str: String,
    pub window_minutes: i64,
    pub config: &'a AlertConfig,
}

impl<'a> AlertCtx<'a> {
    fn events_coll(&self) -> mongodb::Collection<mongodb::bson::Document> {
        self.client
            .database(&self.db)
            .collection::<mongodb::bson::Document>("smtp_events")
    }
}

pub async fn evaluate_alerts(
    client: &Client,
    window_minutes: i64,
    config: &AlertConfig,
) -> Vec<ActiveAlert> {
    let ctx = AlertCtx {
        client,
        db: std::env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string()),
        since_str: (Utc::now() - ChronoDuration::minutes(window_minutes)).to_rfc3339(),
        window_minutes,
        config,
    };

    let mut alerts = Vec::new();
    if let Some(a) = rules::check_bounce_rate(&ctx).await {
        alerts.push(a);
    }
    alerts.extend(rules::check_smtp_spikes(&ctx).await);
    if let Some(a) = rules::check_forbidden_countries(&ctx).await {
        alerts.push(a);
    }
    alerts.extend(rules::check_forbidden_companies(&ctx).await);
    if let Some(a) = rules::check_silent_delivery_failures(&ctx).await {
        alerts.push(a);
    }
    if let Some(a) = rules::check_p95_latency(&ctx).await {
        alerts.push(a);
    }
    alerts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alert_config_defaults() {
        let cfg = AlertConfig::default();
        assert!(cfg.bounce_rate_threshold > 0.0);
        assert!(cfg.p95_total_ms_threshold > 0);
        assert!(cfg.smtp_spike_threshold > 0);
    }
}
