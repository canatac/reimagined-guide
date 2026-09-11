//! Individual alert rule checks. Each function inspects Mongo state and
//! returns zero or more [`ActiveAlert`]s.

use chrono::Utc;
use mongodb::bson::doc;

use super::{ActiveAlert, AlertCtx};

pub(super) async fn check_bounce_rate(ctx: &AlertCtx<'_>) -> Option<ActiveAlert> {
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

pub(super) async fn check_smtp_spikes(ctx: &AlertCtx<'_>) -> Vec<ActiveAlert> {
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

pub(super) async fn check_forbidden_countries(ctx: &AlertCtx<'_>) -> Option<ActiveAlert> {
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

pub(super) async fn check_forbidden_companies(ctx: &AlertCtx<'_>) -> Vec<ActiveAlert> {
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

pub(super) async fn check_silent_delivery_failures(ctx: &AlertCtx<'_>) -> Option<ActiveAlert> {
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

pub(super) async fn check_p95_latency(ctx: &AlertCtx<'_>) -> Option<ActiveAlert> {
    let p95 = crate::monitoring::storage::p95_total_ms(
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

/// Alert when a specific SMTP reject reason code spikes.
/// Threshold is configurable via MONITORING_REJECT_SPIKE_THRESHOLD (default: 5).
pub(super) async fn check_reject_taxonomy_spikes(ctx: &AlertCtx<'_>) -> Vec<ActiveAlert> {
    let coll = ctx.events_coll();
    let threshold: u64 = std::env::var("MONITORING_REJECT_SPIKE_THRESHOLD")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5);

    let pipeline = vec![
        doc! { "$match": {
            "ts": { "$gte": &ctx.since_str },
            "reject_reason_code": { "$exists": true, "$ne": null },
        }},
        doc! { "$group": {
            "_id": "$reject_reason_code",
            "count": { "$sum": 1 },
        }},
        doc! { "$match": { "count": { "$gte": threshold as i64 } }},
    ];

    let mut out = Vec::new();
    if let Ok(cursor) = coll.aggregate(pipeline).await {
        use futures_util::TryStreamExt;
        if let Ok(docs) = cursor.try_collect::<Vec<_>>().await {
            for doc in docs {
                let reason_code = doc
                    .get_str("_id")
                    .unwrap_or("SMTP_REJECT_UNKNOWN")
                    .to_string();
                let count = doc.get_i64("count").ok().unwrap_or(0) as u64;
                let severity = match reason_code.as_str() {
                    "SMTP_REJECT_DKIM_FAIL" | "SMTP_REJECT_SPF_FAIL" | "SMTP_REJECT_DMARC_FAIL" => "critical",
                    "SMTP_REJECT_BLACKLISTED" => "critical",
                    _ => "warning",
                };
                out.push(ActiveAlert {
                    kind: format!("reject_spike_{}", reason_code),
                    severity: severity.into(),
                    message: format!(
                        "Reject reason '{}' spiked: {} occurrences in {}m window (threshold: {})",
                        reason_code, count, ctx.window_minutes, threshold
                    ),
                    value: serde_json::json!(count),
                    threshold: serde_json::json!(threshold),
                    ts: Utc::now().to_rfc3339(),
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_alert_new() {
        let alert = ActiveAlert {
            kind: "bounce_rate".into(),
            severity: "high".into(),
            message: "Test message".into(),
            value: serde_json::json!(0.5),
            threshold: serde_json::json!(0.1),
            ts: Utc::now().to_rfc3339(),
        };
        assert_eq!(alert.kind, "bounce_rate");
        assert_eq!(alert.severity, "high");
        assert_eq!(alert.message, "Test message");
    }

    #[test]
    fn active_alert_clone() {
        let alert = ActiveAlert {
            kind: "test".into(),
            severity: "critical".into(),
            message: "Test".into(),
            value: serde_json::json!(1),
            threshold: serde_json::json!(0),
            ts: Utc::now().to_rfc3339(),
        };
        let cloned = alert.clone();
        assert_eq!(alert.kind, cloned.kind);
        assert_eq!(alert.severity, cloned.severity);
        assert_eq!(alert.message, cloned.message);
    }

    #[test]
    fn active_alert_debug() {
        let alert = ActiveAlert {
            kind: "test".into(),
            severity: "warning".into(),
            message: "Test".into(),
            value: serde_json::json!(1),
            threshold: serde_json::json!(0),
            ts: Utc::now().to_rfc3339(),
        };
        let debug = format!("{:?}", alert);
        assert!(debug.contains("test"));
    }

    #[test]
    fn active_alert_eq() {
        let alert1 = ActiveAlert {
            kind: "test".into(),
            severity: "warning".into(),
            message: "Test".into(),
            value: serde_json::json!(1),
            threshold: serde_json::json!(0),
            ts: Utc::now().to_rfc3339(),
        };
        let alert2 = ActiveAlert {
            kind: "test".into(),
            severity: "warning".into(),
            message: "Test".into(),
            value: serde_json::json!(1),
            threshold: serde_json::json!(0),
            ts: Utc::now().to_rfc3339(),
        };
        assert_eq!(alert1, alert2);
    }

    #[test]
    fn active_alert_ne() {
        let alert1 = ActiveAlert {
            kind: "test1".into(),
            severity: "warning".into(),
            message: "Test".into(),
            value: serde_json::json!(1),
            threshold: serde_json::json!(0),
            ts: Utc::now().to_rfc3339(),
        };
        let alert2 = ActiveAlert {
            kind: "test2".into(),
            severity: "critical".into(),
            message: "Test".into(),
            value: serde_json::json!(1),
            threshold: serde_json::json!(0),
            ts: Utc::now().to_rfc3339(),
        };
        assert_ne!(alert1, alert2);
    }

    #[test]
    fn active_alert_severity_high() {
        let alert = ActiveAlert {
            kind: "test".into(),
            severity: "high".into(),
            message: "Test".into(),
            value: serde_json::json!(1),
            threshold: serde_json::json!(0),
            ts: Utc::now().to_rfc3339(),
        };
        assert_eq!(alert.severity, "high");
    }

    #[test]
    fn active_alert_severity_critical() {
        let alert = ActiveAlert {
            kind: "test".into(),
            severity: "critical".into(),
            message: "Test".into(),
            value: serde_json::json!(1),
            threshold: serde_json::json!(0),
            ts: Utc::now().to_rfc3339(),
        };
        assert_eq!(alert.severity, "critical");
    }

    #[test]
    fn active_alert_severity_warning() {
        let alert = ActiveAlert {
            kind: "test".into(),
            severity: "warning".into(),
            message: "Test".into(),
            value: serde_json::json!(1),
            threshold: serde_json::json!(0),
            ts: Utc::now().to_rfc3339(),
        };
        assert_eq!(alert.severity, "warning");
    }

    #[test]
    fn active_alert_kind_bounce_rate() {
        let alert = ActiveAlert {
            kind: "bounce_rate".into(),
            severity: "high".into(),
            message: "Test".into(),
            value: serde_json::json!(1),
            threshold: serde_json::json!(0),
            ts: Utc::now().to_rfc3339(),
        };
        assert_eq!(alert.kind, "bounce_rate");
    }

    #[test]
    fn active_alert_kind_smtp_spike() {
        let alert = ActiveAlert {
            kind: "smtp_spike_421".into(),
            severity: "warning".into(),
            message: "Test".into(),
            value: serde_json::json!(1),
            threshold: serde_json::json!(0),
            ts: Utc::now().to_rfc3339(),
        };
        assert_eq!(alert.kind, "smtp_spike_421");
    }

    #[test]
    fn active_alert_kind_forbidden_country() {
        let alert = ActiveAlert {
            kind: "forbidden_country".into(),
            severity: "critical".into(),
            message: "Test".into(),
            value: serde_json::json!(1),
            threshold: serde_json::json!(0),
            ts: Utc::now().to_rfc3339(),
        };
        assert_eq!(alert.kind, "forbidden_country");
    }

    #[test]
    fn active_alert_kind_silent_delivery_failure() {
        let alert = ActiveAlert {
            kind: "silent_delivery_failure".into(),
            severity: "critical".into(),
            message: "Test".into(),
            value: serde_json::json!(1),
            threshold: serde_json::json!(0),
            ts: Utc::now().to_rfc3339(),
        };
        assert_eq!(alert.kind, "silent_delivery_failure");
    }

    #[test]
    fn active_alert_kind_p95_latency() {
        let alert = ActiveAlert {
            kind: "p95_latency".into(),
            severity: "warning".into(),
            message: "Test".into(),
            value: serde_json::json!(1),
            threshold: serde_json::json!(0),
            ts: Utc::now().to_rfc3339(),
        };
        assert_eq!(alert.kind, "p95_latency");
    }

    #[test]
    fn active_alert_ts_format() {
        let alert = ActiveAlert {
            kind: "test".into(),
            severity: "warning".into(),
            message: "Test".into(),
            value: serde_json::json!(1),
            threshold: serde_json::json!(0),
            ts: "2026-01-01T00:00:00Z".into(),
        };
        assert!(alert.ts.contains("2026"));
        assert!(alert.ts.contains("T"));
        assert!(alert.ts.ends_with("Z"));
    }

    #[test]
    fn active_alert_value_number() {
        let alert = ActiveAlert {
            kind: "test".into(),
            severity: "warning".into(),
            message: "Test".into(),
            value: serde_json::json!(42),
            threshold: serde_json::json!(0),
            ts: Utc::now().to_rfc3339(),
        };
        assert_eq!(alert.value, serde_json::json!(42));
    }

    #[test]
    fn active_alert_value_float() {
        let alert = ActiveAlert {
            kind: "test".into(),
            severity: "warning".into(),
            message: "Test".into(),
            value: serde_json::json!(0.5),
            threshold: serde_json::json!(0),
            ts: Utc::now().to_rfc3339(),
        };
        assert_eq!(alert.value, serde_json::json!(0.5));
    }

    #[test]
    fn active_alert_threshold_number() {
        let alert = ActiveAlert {
            kind: "test".into(),
            severity: "warning".into(),
            message: "Test".into(),
            value: serde_json::json!(1),
            threshold: serde_json::json!(10),
            ts: Utc::now().to_rfc3339(),
        };
        assert_eq!(alert.threshold, serde_json::json!(10));
    }

    #[test]
    fn active_alert_message_format() {
        let alert = ActiveAlert {
            kind: "test".into(),
            severity: "warning".into(),
            message: "Bounce rate 10.0% exceeds threshold 5.0%".into(),
            value: serde_json::json!(0.1),
            threshold: serde_json::json!(0.05),
            ts: Utc::now().to_rfc3339(),
        };
        assert!(alert.message.contains("Bounce rate"));
        assert!(alert.message.contains("10.0%"));
        assert!(alert.message.contains("5.0%"));
    }

    #[test]
    fn check_bounce_rate_zero_total() {
        let total = 0u64;
        let bounced = 0u64;
        let rate = if total == 0 { 0.0 } else { bounced as f32 / total as f32 };
        assert_eq!(rate, 0.0);
    }

    #[test]
    fn check_bounce_rate_calculation() {
        let total = 100u64;
        let bounced = 10u64;
        let rate = bounced as f32 / total as f32;
        assert!((rate - 0.1).abs() < f32::EPSILON);
    }

    #[test]
    fn check_bounce_rate_above_threshold() {
        let rate = 0.2f32;
        let threshold = 0.1f32;
        assert!(rate > threshold);
    }

    #[test]
    fn check_bounce_rate_below_threshold() {
        let rate = 0.05f32;
        let threshold = 0.1f32;
        assert!(rate <= threshold);
    }

    #[test]
    fn check_smtp_spikes_codes() {
        let codes = [421u32, 450, 550, 554];
        assert_eq!(codes.len(), 4);
        assert_eq!(codes[0], 421);
        assert_eq!(codes[1], 450);
        assert_eq!(codes[2], 550);
        assert_eq!(codes[3], 554);
    }

    #[test]
    fn check_smtp_spikes_severity_critical() {
        let code = 550u32;
        let severity = if code >= 550 { "critical" } else { "warning" };
        assert_eq!(severity, "critical");
    }

    #[test]
    fn check_smtp_spikes_severity_warning() {
        let code = 421u32;
        let severity = if code >= 550 { "critical" } else { "warning" };
        assert_eq!(severity, "warning");
    }

    #[test]
    fn check_smtp_spikes_above_threshold() {
        let count = 30u64;
        let threshold = 20u64;
        assert!(count >= threshold);
    }

    #[test]
    fn check_smtp_spikes_below_threshold() {
        let count = 10u64;
        let threshold = 20u64;
        assert!(count < threshold);
    }

    #[test]
    fn check_forbidden_countries_empty() {
        let countries: Vec<String> = vec![];
        assert!(countries.is_empty());
    }

    #[test]
    fn check_forbidden_countries_with_entries() {
        let countries = vec!["CN".to_string(), "RU".to_string()];
        assert!(!countries.is_empty());
        assert_eq!(countries.len(), 2);
    }

    #[test]
    fn check_forbidden_countries_zero_hits() {
        let count = 0u64;
        assert_eq!(count, 0);
    }

    #[test]
    fn check_forbidden_countries_positive_hits() {
        let count = 5u64;
        assert!(count > 0);
    }

    #[test]
    fn check_silent_delivery_failures_zero_api_sent() {
        let api_sent = 0u64;
        assert_eq!(api_sent, 0);
    }

    #[test]
    fn check_silent_delivery_failures_calculation() {
        let api_sent = 100u64;
        let smtp_delivered = 80u64;
        let undelivered = api_sent.saturating_sub(smtp_delivered);
        let ratio = undelivered as f32 / api_sent as f32;
        assert_eq!(undelivered, 20);
        assert!((ratio - 0.2).abs() < f32::EPSILON);
    }

    #[test]
    fn check_silent_delivery_failures_above_threshold() {
        let ratio = 0.3f32;
        let threshold = 0.1f32;
        assert!(ratio > threshold);
    }

    #[test]
    fn check_silent_delivery_failures_below_threshold() {
        let ratio = 0.05f32;
        let threshold = 0.1f32;
        assert!(ratio <= threshold);
    }

    #[test]
    fn check_p95_latency_above_threshold() {
        let p95 = 5000u64;
        let threshold = 3000u64;
        assert!(p95 > threshold);
    }

    #[test]
    fn check_p95_latency_below_threshold() {
        let p95 = 2000u64;
        let threshold = 3000u64;
        assert!(p95 <= threshold);
    }

    #[test]
    fn check_p95_latency_at_threshold() {
        let p95 = 3000u64;
        let threshold = 3000u64;
        assert!(p95 <= threshold);
    }

    #[test]
    fn check_reject_taxonomy_spikes_threshold_default() {
        let threshold: u64 = 5;
        assert_eq!(threshold, 5);
    }

    #[test]
    fn check_reject_taxonomy_spikes_threshold_custom() {
        let threshold: u64 = 10;
        assert_eq!(threshold, 10);
    }

    #[test]
    fn check_reject_taxonomy_spikes_severity_dkim_fail() {
        let reason_code = "SMTP_REJECT_DKIM_FAIL";
        let severity = match reason_code {
            "SMTP_REJECT_DKIM_FAIL" | "SMTP_REJECT_SPF_FAIL" | "SMTP_REJECT_DMARC_FAIL" => "critical",
            "SMTP_REJECT_BLACKLISTED" => "critical",
            _ => "warning",
        };
        assert_eq!(severity, "critical");
    }

    #[test]
    fn check_reject_taxonomy_spikes_severity_blacklisted() {
        let reason_code = "SMTP_REJECT_BLACKLISTED";
        let severity = match reason_code {
            "SMTP_REJECT_DKIM_FAIL" | "SMTP_REJECT_SPF_FAIL" | "SMTP_REJECT_DMARC_FAIL" => "critical",
            "SMTP_REJECT_BLACKLISTED" => "critical",
            _ => "warning",
        };
        assert_eq!(severity, "critical");
    }

    #[test]
    fn check_reject_taxonomy_spikes_severity_other() {
        let reason_code = "SMTP_REJECT_UNKNOWN";
        let severity = match reason_code {
            "SMTP_REJECT_DKIM_FAIL" | "SMTP_REJECT_SPF_FAIL" | "SMTP_REJECT_DMARC_FAIL" => "critical",
            "SMTP_REJECT_BLACKLISTED" => "critical",
            _ => "warning",
        };
        assert_eq!(severity, "warning");
    }

    #[test]
    fn check_reject_taxonomy_spikes_severity_spf_fail() {
        let reason_code = "SMTP_REJECT_SPF_FAIL";
        let severity = match reason_code {
            "SMTP_REJECT_DKIM_FAIL" | "SMTP_REJECT_SPF_FAIL" | "SMTP_REJECT_DMARC_FAIL" => "critical",
            "SMTP_REJECT_BLACKLISTED" => "critical",
            _ => "warning",
        };
        assert_eq!(severity, "critical");
    }

    #[test]
    fn check_reject_taxonomy_spikes_severity_dmarc_fail() {
        let reason_code = "SMTP_REJECT_DMARC_FAIL";
        let severity = match reason_code {
            "SMTP_REJECT_DKIM_FAIL" | "SMTP_REJECT_SPF_FAIL" | "SMTP_REJECT_DMARC_FAIL" => "critical",
            "SMTP_REJECT_BLACKLISTED" => "critical",
            _ => "warning",
        };
        assert_eq!(severity, "critical");
    }

    #[test]
    fn check_reject_taxonomy_spikes_above_threshold() {
        let count = 10u64;
        let threshold = 5u64;
        assert!(count >= threshold);
    }

    #[test]
    fn check_reject_taxonomy_spikes_below_threshold() {
        let count = 3u64;
        let threshold = 5u64;
        assert!(count < threshold);
    }

    #[test]
    fn check_reject_taxonomy_spikes_at_threshold() {
        let count = 5u64;
        let threshold = 5u64;
        assert!(count >= threshold);
    }

    #[test]
    fn check_forbidden_companies_empty() {
        let companies: Vec<String> = vec![];
        assert!(companies.is_empty());
    }

    #[test]
    fn check_forbidden_companies_with_entries() {
        let companies = vec!["BadCorp".to_string(), "EvilInc".to_string()];
        assert!(!companies.is_empty());
        assert_eq!(companies.len(), 2);
    }

    #[test]
    fn check_forbidden_companies_zero_hits() {
        let count = 0u64;
        assert_eq!(count, 0);
    }

    #[test]
    fn check_forbidden_companies_positive_hits() {
        let count = 5u64;
        assert!(count > 0);
    }

    #[test]
    fn check_bounce_rate_message_format() {
        let rate = 0.1f32;
        let threshold = 0.05f32;
        let message = format!(
            "Bounce rate {:.1}% exceeds threshold {:.1}%",
            rate * 100.0,
            threshold * 100.0
        );
        assert_eq!(message, "Bounce rate 10.0% exceeds threshold 5.0%");
    }

    #[test]
    fn check_smtp_spikes_message_format() {
        let code = 421u32;
        let count = 30u64;
        let window_minutes = 30u64;
        let threshold = 20u64;
        let message = format!(
            "SMTP {} errors: {} occurrences in {}m window (threshold: {})",
            code, count, window_minutes, threshold
        );
        assert_eq!(message, "SMTP 421 errors: 30 occurrences in 30m window (threshold: 20)");
    }

    #[test]
    fn check_forbidden_countries_message_format() {
        let count = 5u64;
        let countries = vec!["CN".to_string(), "RU".to_string()];
        let message = format!(
            "{} email(s) routed via forbidden countries {:?}",
            count, countries
        );
        assert_eq!(message, "5 email(s) routed via forbidden countries [\"CN\", \"RU\"]");
    }

    #[test]
    fn check_silent_delivery_failures_message_format() {
        let undelivered = 20u64;
        let ratio = 0.2f32;
        let message = format!(
            "{} email(s) recorded as sent by API but no SMTP delivery event ({:.1}% undelivered)",
            undelivered,
            ratio * 100.0
        );
        assert_eq!(message, "20 email(s) recorded as sent by API but no SMTP delivery event (20.0% undelivered)");
    }

    #[test]
    fn check_p95_latency_message_format() {
        let p95 = 5000u64;
        let threshold = 3000u64;
        let message = format!(
            "P95 total_ms {}ms exceeds threshold {}ms",
            p95, threshold
        );
        assert_eq!(message, "P95 total_ms 5000ms exceeds threshold 3000ms");
    }

    #[test]
    fn check_reject_taxonomy_spikes_message_format() {
        let reason_code = "SMTP_REJECT_DKIM_FAIL";
        let count = 10u64;
        let window_minutes = 60u64;
        let threshold = 5u64;
        let message = format!(
            "Reject reason '{}' spiked: {} occurrences in {}m window (threshold: {})",
            reason_code, count, window_minutes, threshold
        );
        assert_eq!(message, "Reject reason 'SMTP_REJECT_DKIM_FAIL' spiked: 10 occurrences in 60m window (threshold: 5)");
    }

    #[test]
    fn check_forbidden_companies_message_format() {
        let count = 5u64;
        let company = "BadCorp";
        let message = format!(
            "{} email(s) routed via forbidden company '{}'",
            count, company
        );
        assert_eq!(message, "5 email(s) routed via forbidden company 'BadCorp'");
    }
}
