use chrono::{Duration as ChronoDuration, Utc};
use mongodb::bson::doc;
use mongodb::Client;
use serde::{Deserialize, Serialize};

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
struct AlertCtx<'a> {
    client: &'a Client,
    db: String,
    since_str: String,
    window_minutes: i64,
    config: &'a AlertConfig,
}

impl<'a> AlertCtx<'a> {
    fn events_coll(&self) -> mongodb::Collection<mongodb::bson::Document> {
        self.client
            .database(&self.db)
            .collection::<mongodb::bson::Document>("smtp_events")
    }
}

async fn check_bounce_rate(ctx: &AlertCtx<'_>) -> Option<ActiveAlert> {
    let coll = ctx.events_coll();
    let total = coll
        .count_documents(doc! { "ts": { "$gte": &ctx.since_str } })
        .await
        .unwrap_or(0);
    if total == 0 {
        return None;
    }
    let bounced = coll
        .count_documents(doc! { "ts": { "$gte": &ctx.since_str }, "status": "bounced" })
        .await
        .unwrap_or(0);
    let rate = bounced as f32 / total as f32;
    if rate <= ctx.config.bounce_rate_threshold {
        return None;
    }
    Some(ActiveAlert {
        kind: "bounce_rate".into(),
        severity: "high".into(),
        message: format!(
            "Bounce rate {:.1}% exceeds threshold {:.1}%",
            rate * 100.0,
            ctx.config.bounce_rate_threshold * 100.0
        ),
        value: serde_json::json!(rate),
        threshold: serde_json::json!(ctx.config.bounce_rate_threshold),
        ts: Utc::now().to_rfc3339(),
    })
}

async fn check_smtp_spikes(ctx: &AlertCtx<'_>) -> Vec<ActiveAlert> {
    let coll = ctx.events_coll();
    let mut out = Vec::new();
    for &code in &[421u32, 450, 550, 554] {
        let count = coll
            .count_documents(doc! {
                "ts": { "$gte": &ctx.since_str },
                "smtp_code": code as i32,
            })
            .await
            .unwrap_or(0);
        if count >= ctx.config.smtp_spike_threshold {
            let severity = if code >= 550 { "critical" } else { "warning" };
            out.push(ActiveAlert {
                kind: format!("smtp_spike_{}", code),
                severity: severity.into(),
                message: format!(
                    "SMTP {} errors: {} occurrences in {}m window (threshold: {})",
                    code, count, ctx.window_minutes, ctx.config.smtp_spike_threshold
                ),
                value: serde_json::json!(count),
                threshold: serde_json::json!(ctx.config.smtp_spike_threshold),
                ts: Utc::now().to_rfc3339(),
            });
        }
    }
    out
}

async fn check_forbidden_countries(ctx: &AlertCtx<'_>) -> Option<ActiveAlert> {
    if ctx.config.forbidden_countries.is_empty() {
        return None;
    }
    let countries_bson: Vec<_> = ctx
        .config
        .forbidden_countries
        .iter()
        .map(|c| mongodb::bson::Bson::String(c.clone()))
        .collect();
    let count = ctx
        .events_coll()
        .count_documents(doc! {
            "ts": { "$gte": &ctx.since_str },
            "country": { "$in": countries_bson },
        })
        .await
        .unwrap_or(0);
    if count == 0 {
        return None;
    }
    Some(ActiveAlert {
        kind: "forbidden_country".into(),
        severity: "critical".into(),
        message: format!(
            "{} email(s) routed via forbidden countries {:?}",
            count, ctx.config.forbidden_countries
        ),
        value: serde_json::json!(count),
        threshold: serde_json::json!(0),
        ts: Utc::now().to_rfc3339(),
    })
}

async fn check_forbidden_companies(ctx: &AlertCtx<'_>) -> Vec<ActiveAlert> {
    let coll = ctx.events_coll();
    let mut out = Vec::new();
    for company in &ctx.config.forbidden_companies {
        let count = coll
            .count_documents(doc! {
                "ts": { "$gte": &ctx.since_str },
                "company": { "$regex": company.as_str(), "$options": "i" },
            })
            .await
            .unwrap_or(0);
        if count > 0 {
            out.push(ActiveAlert {
                kind: "forbidden_company".to_string(),
                severity: "critical".into(),
                message: format!(
                    "{} email(s) routed via forbidden company '{}'",
                    count, company
                ),
                value: serde_json::json!(count),
                threshold: serde_json::json!(0),
                ts: Utc::now().to_rfc3339(),
            });
        }
    }
    out
}

async fn check_silent_delivery_failures(ctx: &AlertCtx<'_>) -> Option<ActiveAlert> {
    let mail_coll = ctx
        .client
        .database(&ctx.db)
        .collection::<mongodb::bson::Document>("mail_events");
    let api_sent = mail_coll
        .count_documents(doc! { "timestamp": { "$gte": &ctx.since_str }, "kind": "sent" })
        .await
        .unwrap_or(0);
    if api_sent == 0 {
        return None;
    }
    let smtp_delivered = ctx
        .events_coll()
        .count_documents(doc! { "ts": { "$gte": &ctx.since_str }, "event_type": "delivered" })
        .await
        .unwrap_or(0);
    let undelivered = api_sent.saturating_sub(smtp_delivered);
    let ratio = undelivered as f32 / api_sent as f32;
    if ratio <= ctx.config.undelivered_ratio_threshold {
        return None;
    }
    Some(ActiveAlert {
        kind: "silent_delivery_failure".into(),
        severity: "critical".into(),
        message: format!(
            "{} email(s) recorded as sent by API but no SMTP delivery event ({:.1}% undelivered)",
            undelivered,
            ratio * 100.0
        ),
        value: serde_json::json!(undelivered),
        threshold: serde_json::json!(ctx.config.undelivered_ratio_threshold),
        ts: Utc::now().to_rfc3339(),
    })
}

async fn check_p95_latency(ctx: &AlertCtx<'_>) -> Option<ActiveAlert> {
    let p95 = super::storage::p95_total_ms(
        ctx.client,
        doc! { "ts": { "$gte": &ctx.since_str } },
        1000,
    )
    .await?;
    if p95 <= ctx.config.p95_total_ms_threshold {
        return None;
    }
    Some(ActiveAlert {
        kind: "p95_latency".into(),
        severity: "warning".into(),
        message: format!(
            "P95 total_ms {}ms exceeds threshold {}ms",
            p95, ctx.config.p95_total_ms_threshold
        ),
        value: serde_json::json!(p95),
        threshold: serde_json::json!(ctx.config.p95_total_ms_threshold),
        ts: Utc::now().to_rfc3339(),
    })
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
    if let Some(a) = check_bounce_rate(&ctx).await {
        alerts.push(a);
    }
    alerts.extend(check_smtp_spikes(&ctx).await);
    if let Some(a) = check_forbidden_countries(&ctx).await {
        alerts.push(a);
    }
    alerts.extend(check_forbidden_companies(&ctx).await);
    if let Some(a) = check_silent_delivery_failures(&ctx).await {
        alerts.push(a);
    }
    if let Some(a) = check_p95_latency(&ctx).await {
        alerts.push(a);
    }
    alerts
}

// ---------------------------------------------------------------------------
// Env helpers
// ---------------------------------------------------------------------------

fn env_f32(key: &str, default: f32) -> f32 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_list(key: &str) -> Vec<String> {
    std::env::var(key)
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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
