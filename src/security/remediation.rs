use chrono::Utc;
use futures_util::TryStreamExt;
use mongodb::{bson::{self, doc}, Client};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{RemediationAction, RemediationLevel, SecurityAlert, AlertStatus};

// ---------------------------------------------------------------------------
// Tenant remediation state persisted in `tenant_state` collection
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantState {
    pub tenant_id: String,
    pub level: u8,
    pub action: RemediationAction,
    pub reason: String,
    pub alert_id: String,
    pub applied_at: String,
    pub expires_at: Option<String>,
    pub rolled_back: bool,
}

pub async fn apply_remediation(client: &Client, alert: &mut SecurityAlert) {
    if !super::enforce_mode() {
        // Observe mode: log intent but do not enforce
        log_audit(client, alert, "observe_mode_no_action").await;
        return;
    }

    let db = std::env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let coll = client
        .database(&db)
        .collection::<bson::Document>("tenant_state");

    if let Some(ref tid) = alert.tenant_id.clone() {
        let expires_at = alert.action_duration_s.map(|s| {
            (Utc::now() + chrono::Duration::seconds(s as i64)).to_rfc3339()
        });

        let state = TenantState {
            tenant_id: tid.clone(),
            level: alert.remediation_level,
            action: alert.action.clone(),
            reason: format!("{} — {}", alert.rule_id, alert.rule_name),
            alert_id: alert.id.clone(),
            applied_at: Utc::now().to_rfc3339(),
            expires_at,
            rolled_back: false,
        };

        if let Ok(doc) = bson::to_document(&state) {
            // Upsert: replace previous state if level is higher
            let filter = doc! { "tenant_id": tid.as_str() };
            let existing_level = coll
                .find_one(filter.clone())
                .await
                .unwrap_or(None)
                .and_then(|d| d.get_i64("level").ok())
                .unwrap_or(0) as u8;

            if alert.remediation_level >= existing_level {
                let _ = coll
                    .replace_one(filter, doc.clone())
                    .upsert(true)
                    .await;
            }
        }
    }

    log_audit(client, alert, "applied").await;
}

pub async fn rollback_remediation(client: &Client, alert_id: &str) -> Result<(), String> {
    let db = std::env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let coll = client
        .database(&db)
        .collection::<bson::Document>("tenant_state");

    let alert_coll = client
        .database(&db)
        .collection::<bson::Document>("security_alerts");

    // Find the alert
    let alert_doc = alert_coll
        .find_one(doc! { "id": alert_id })
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "Alert not found".to_string())?;

    let tenant_id = alert_doc.get_str("tenant_id").unwrap_or("");

    // Remove tenant_state for this tenant+alert
    let _ = coll
        .delete_one(doc! { "tenant_id": tenant_id, "alert_id": alert_id })
        .await;

    // Mark alert as rolled back
    let _ = alert_coll
        .update_one(
            doc! { "id": alert_id },
            doc! { "$set": { "rolled_back": true, "status": "rolled_back" } },
        )
        .await;

    // Audit
    let audit_coll = client
        .database(&db)
        .collection::<bson::Document>("security_audit");
    let _ = audit_coll
        .insert_one(doc! {
            "id": Uuid::new_v4().to_string(),
            "ts": Utc::now().to_rfc3339(),
            "action": "rollback",
            "alert_id": alert_id,
            "tenant_id": tenant_id,
            "operator": "auto",
        })
        .await;

    Ok(())
}

/// Sweep expired tenant states and restore access.
pub async fn cleanup_expired_states(client: &Client) {
    let db = std::env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let coll = client
        .database(&db)
        .collection::<bson::Document>("tenant_state");

    let now = Utc::now().to_rfc3339();
    let filter = doc! {
        "expires_at": { "$lte": &now },
        "rolled_back": false,
    };
    if let Ok(mut cursor) = coll.find(filter.clone()).await {
        while let Ok(Some(doc)) = cursor.try_next().await {
            let tid = doc.get_str("tenant_id").unwrap_or("");
            let aid = doc.get_str("alert_id").unwrap_or("");
            eprintln!("monitoring: auto-expiring remediation for tenant={} alert={}", tid, aid);
        }
    }
    let _ = coll.delete_many(filter).await;
}

async fn log_audit(client: &Client, alert: &SecurityAlert, action: &str) {
    let db = std::env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let coll = client
        .database(&db)
        .collection::<bson::Document>("security_audit");

    let _ = coll
        .insert_one(doc! {
            "id": Uuid::new_v4().to_string(),
            "ts": Utc::now().to_rfc3339(),
            "action": action,
            "alert_id": &alert.id,
            "rule_id": &alert.rule_id,
            "tenant_id": alert.tenant_id.as_deref().unwrap_or(""),
            "remediation_level": alert.remediation_level as i32,
            "enforce_mode": super::enforce_mode(),
        })
        .await;
}
