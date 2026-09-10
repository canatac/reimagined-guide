use futures_util::TryStreamExt;
use mongodb::{bson::{self, doc}, Client};

use super::SecurityAlert;

const ALERTS_COLL: &str = "security_alerts";

fn db() -> String {
    std::env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string())
}

pub async fn ensure_indexes(client: &Client) {
    use mongodb::IndexModel;
    let coll = client.database(&db()).collection::<bson::Document>(ALERTS_COLL);
    for idx in [
        doc! { "ts": -1 },
        doc! { "rule_id": 1, "ts": -1 },
        doc! { "tenant_id": 1, "ts": -1 },
        doc! { "severity": 1, "ts": -1 },
        doc! { "status": 1 },
    ] {
        let _ = coll.create_index(IndexModel::builder().keys(idx).build()).await;
    }
}

/// Persist alert to MongoDB (append-only, never update).
pub async fn persist_alert(client: &Client, alert: &SecurityAlert) {
    let coll = client.database(&db()).collection::<bson::Document>(ALERTS_COLL);
    if let Ok(doc) = bson::to_document(alert) {
        if let Err(e) = coll.insert_one(doc).await {
            eprintln!("security: persist_alert error: {}", e);
        }
    }
}

pub async fn query_active_alerts(client: &Client, limit: i64) -> Vec<SecurityAlert> {
    let coll = client.database(&db()).collection::<bson::Document>(ALERTS_COLL);
    match coll
        .find(doc! { "status": "active" })
        .sort(doc! { "ts": -1 })
        .limit(limit)
        .await
    {
        Ok(cursor) => cursor
            .try_collect::<Vec<_>>()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter_map(|d| bson::from_document::<SecurityAlert>(d).ok())
            .collect(),
        Err(_) => vec![],
    }
}

pub async fn query_alerts(
    client: &Client,
    filter: bson::Document,
    page: u32,
    page_size: u32,
) -> Vec<SecurityAlert> {
    let coll = client.database(&db()).collection::<bson::Document>(ALERTS_COLL);
    let skip = ((page.saturating_sub(1)) * page_size) as u64;
    match coll
        .find(filter)
        .sort(doc! { "ts": -1 })
        .skip(skip)
        .limit(page_size as i64)
        .await
    {
        Ok(cursor) => cursor
            .try_collect::<Vec<_>>()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter_map(|d| bson::from_document::<SecurityAlert>(d).ok())
            .collect(),
        Err(_) => vec![],
    }
}

/// Spawn background engine: evaluate all rules every SECURITY_EVAL_INTERVAL_S.
pub fn start_engine(client: std::sync::Arc<Client>) {
    let interval_s = std::env::var("SECURITY_EVAL_INTERVAL_S")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(60);

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_s));
        ticker.tick().await; // skip first immediate tick

        loop {
            ticker.tick().await;

            if !super::security_enabled() {
                continue;
            }

            let ctx = super::rules::RuleContext {
                client: &client,
                tenant_id: None,
            };

            let alerts = super::rules::evaluate_all(&ctx).await;

            for mut alert in alerts {
                alert.stamp_audit_hash();
                persist_alert(&client, &alert).await;
                super::emit_alert(alert.clone());

                if super::enforce_mode() {
                    super::remediation::apply_remediation(&client, &mut alert.clone()).await;
                }
            }

            // Cleanup expired remediations
            super::remediation::cleanup_expired_states(&client).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn db_name_default() {
        std::env::remove_var("MONGODB_DATABASE");
        assert_eq!(db_name(), "mailserver");
    }

    #[test]
    fn db_name_custom() {
        std::env::set_var("MONGODB_DATABASE", "custom_audit_db");
        assert_eq!(db_name(), "custom_audit_db");
        std::env::remove_var("MONGODB_DATABASE");
    }

    #[test]
    fn alerts_coll_name() {
        assert_eq!(ALERTS_COLL, "security_alerts");
    }

    #[test]
    fn security_alert_roundtrip() {
        let alert = crate::security::SecurityAlert::new(
            "rule-test",
            "Test Rule",
            crate::security::SecuritySeverity::High,
            crate::security::RemediationLevel::ALERT,
        );
        let doc = bson::to_document(&alert).expect("serialize");
        let parsed: crate::security::SecurityAlert = bson::from_document(doc).expect("deserialize");
        assert_eq!(parsed.rule_id, "rule-test");
        assert_eq!(parsed.rule_name, "Test Rule");
    }

    #[test]
    fn security_alert_with_tenant_roundtrip() {
        let alert = crate::security::SecurityAlert::new(
            "rule-tenant",
            "Tenant Rule",
            crate::security::SecuritySeverity::Critical,
            crate::security::RemediationLevel::BLOCK,
        )
        .with_tenant("tenant-123");
        let doc = bson::to_document(&alert).expect("serialize");
        let parsed: crate::security::SecurityAlert = bson::from_document(doc).expect("deserialize");
        assert_eq!(parsed.tenant_id, Some("tenant-123".to_string()));
    }

    #[test]
    fn security_alert_with_signal_roundtrip() {
        let signal = serde_json::json!({ "ratio": 0.95, "count": 100 });
        let alert = crate::security::SecurityAlert::new(
            "rule-signal",
            "Signal Rule",
            crate::security::SecuritySeverity::Medium,
            crate::security::RemediationLevel::THROTTLE,
        )
        .with_signal(signal.clone());
        let doc = bson::to_document(&alert).expect("serialize");
        let parsed: crate::security::SecurityAlert = bson::from_document(doc).expect("deserialize");
        assert_eq!(parsed.signal, signal);
    }

    #[test]
    fn security_alert_with_duration_roundtrip() {
        let alert = crate::security::SecurityAlert::new(
            "rule-duration",
            "Duration Rule",
            crate::security::SecuritySeverity::Low,
            crate::security::RemediationLevel::ALERT,
        )
        .with_duration(600);
        let doc = bson::to_document(&alert).expect("serialize");
        let parsed: crate::security::SecurityAlert = bson::from_document(doc).expect("deserialize");
        assert_eq!(parsed.action_duration_s, Some(600));
    }

    #[test]
    fn security_alert_status_active() {
        let alert = crate::security::SecurityAlert::new(
            "rule-status",
            "Status Rule",
            crate::security::SecuritySeverity::Info,
            crate::security::RemediationLevel::ALERT,
        );
        assert_eq!(alert.status, crate::security::AlertStatus::Active);
        assert!(!alert.rolled_back);
    }

    #[test]
    fn security_alert_id_is_uuid() {
        let alert = crate::security::SecurityAlert::new(
            "rule-id",
            "ID Rule",
            crate::security::SecuritySeverity::High,
            crate::security::RemediationLevel::ALERT,
        );
        assert_eq!(alert.id.len(), 36);
        assert!(alert.id.contains('-'));
    }

    #[test]
    fn security_alert_timestamp_is_rfc3339() {
        let alert = crate::security::SecurityAlert::new(
            "rule-ts",
            "Timestamp Rule",
            crate::security::SecuritySeverity::Medium,
            crate::security::RemediationLevel::ALERT,
        );
        assert!(chrono::DateTime::parse_from_rfc3339(&alert.ts).is_ok());
    }
}
