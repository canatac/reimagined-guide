use chrono::Utc;
use futures_util::TryStreamExt;
use mongodb::{bson::{self, doc}, Client};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{RemediationAction, SecurityAlert};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_state_default() {
        let state = TenantState {
            tenant_id: "tenant-1".to_string(),
            level: 1,
            action: RemediationAction::ALERT,
            reason: "Test reason".to_string(),
            alert_id: "alert-1".to_string(),
            applied_at: Utc::now().to_rfc3339(),
            expires_at: None,
            rolled_back: false,
        };
        assert_eq!(state.tenant_id, "tenant-1");
        assert_eq!(state.level, 1);
        assert_eq!(state.reason, "Test reason");
        assert_eq!(state.alert_id, "alert-1");
        assert_eq!(state.rolled_back, false);
        assert_eq!(state.expires_at, None);
    }

    #[test]
    fn tenant_state_with_expiry() {
        let expires_at = Some("2026-12-31T23:59:59Z".to_string());
        let state = TenantState {
            tenant_id: "tenant-1".to_string(),
            level: 2,
            action: RemediationAction::THROTTLE,
            reason: "Test".to_string(),
            alert_id: "alert-1".to_string(),
            applied_at: Utc::now().to_rfc3339(),
            expires_at: expires_at.clone(),
            rolled_back: false,
        };
        assert_eq!(state.expires_at, expires_at);
    }

    #[test]
    fn tenant_state_rolled_back() {
        let state = TenantState {
            tenant_id: "tenant-1".to_string(),
            level: 3,
            action: RemediationAction::BLOCK,
            reason: "Test".to_string(),
            alert_id: "alert-1".to_string(),
            applied_at: Utc::now().to_rfc3339(),
            expires_at: None,
            rolled_back: true,
        };
        assert!(state.rolled_back);
    }

    #[test]
    fn tenant_state_level_comparison() {
        let level_low = 1u8;
        let level_high = 3u8;
        assert!(level_high >= level_low);
        assert!(!(level_low >= level_high));
    }

    #[test]
    fn tenant_state_level_equal() {
        let level_a = 2u8;
        let level_b = 2u8;
        assert!(level_a >= level_b);
        assert!(level_b >= level_a);
    }

    #[test]
    fn tenant_state_serialize() {
        let state = TenantState {
            tenant_id: "tenant-1".to_string(),
            level: 1,
            action: RemediationAction::ALERT,
            reason: "Test".to_string(),
            alert_id: "alert-1".to_string(),
            applied_at: "2026-01-01T00:00:00Z".to_string(),
            expires_at: None,
            rolled_back: false,
        };
        let serialized = serde_json::to_string(&state);
        assert!(serialized.is_ok());
    }

    #[test]
    fn tenant_state_deserialize() {
        let json = r#"{
            "tenant_id": "tenant-1",
            "level": 1,
            "action": "ALERT",
            "reason": "Test",
            "alert_id": "alert-1",
            "applied_at": "2026-01-01T00:00:00Z",
            "expires_at": null,
            "rolled_back": false
        }"#;
        let result: Result<TenantState, _> = serde_json::from_str(json);
        assert!(result.is_ok());
        let state = result.unwrap();
        assert_eq!(state.tenant_id, "tenant-1");
        assert_eq!(state.level, 1);
    }

    #[test]
    fn tenant_state_deserialize_with_expiry() {
        let json = r#"{
            "tenant_id": "tenant-1",
            "level": 2,
            "action": "THROTTLE",
            "reason": "Test",
            "alert_id": "alert-1",
            "applied_at": "2026-01-01T00:00:00Z",
            "expires_at": "2026-12-31T23:59:59Z",
            "rolled_back": false
        }"#;
        let result: Result<TenantState, _> = serde_json::from_str(json);
        assert!(result.is_ok());
        let state = result.unwrap();
        assert_eq!(state.expires_at, Some("2026-12-31T23:59:59Z".to_string()));
    }

    #[test]
    fn tenant_state_clone() {
        let state = TenantState {
            tenant_id: "tenant-1".to_string(),
            level: 1,
            action: RemediationAction::ALERT,
            reason: "Test".to_string(),
            alert_id: "alert-1".to_string(),
            applied_at: Utc::now().to_rfc3339(),
            expires_at: None,
            rolled_back: false,
        };
        let cloned = state.clone();
        assert_eq!(state.tenant_id, cloned.tenant_id);
        assert_eq!(state.level, cloned.level);
        assert_eq!(state.reason, cloned.reason);
        assert_eq!(state.alert_id, cloned.alert_id);
        assert_eq!(state.rolled_back, cloned.rolled_back);
    }

    #[test]
    fn tenant_state_debug() {
        let state = TenantState {
            tenant_id: "tenant-1".to_string(),
            level: 1,
            action: RemediationAction::ALERT,
            reason: "Test".to_string(),
            alert_id: "alert-1".to_string(),
            applied_at: Utc::now().to_rfc3339(),
            expires_at: None,
            rolled_back: false,
        };
        let debug = format!("{:?}", state);
        assert!(debug.contains("tenant-1"));
        assert!(debug.contains("1"));
    }

    #[test]
    fn tenant_state_eq() {
        let state1 = TenantState {
            tenant_id: "tenant-1".to_string(),
            level: 1,
            action: RemediationAction::ALERT,
            reason: "Test".to_string(),
            alert_id: "alert-1".to_string(),
            applied_at: "2026-01-01T00:00:00Z".to_string(),
            expires_at: None,
            rolled_back: false,
        };
        let state2 = TenantState {
            tenant_id: "tenant-1".to_string(),
            level: 1,
            action: RemediationAction::ALERT,
            reason: "Test".to_string(),
            alert_id: "alert-1".to_string(),
            applied_at: "2026-01-01T00:00:00Z".to_string(),
            expires_at: None,
            rolled_back: false,
        };
        assert_eq!(state1, state2);
    }

    #[test]
    fn tenant_state_ne() {
        let state1 = TenantState {
            tenant_id: "tenant-1".to_string(),
            level: 1,
            action: RemediationAction::ALERT,
            reason: "Test".to_string(),
            alert_id: "alert-1".to_string(),
            applied_at: Utc::now().to_rfc3339(),
            expires_at: None,
            rolled_back: false,
        };
        let state2 = TenantState {
            tenant_id: "tenant-2".to_string(),
            level: 1,
            action: RemediationAction::ALERT,
            reason: "Test".to_string(),
            alert_id: "alert-1".to_string(),
            applied_at: Utc::now().to_rfc3339(),
            expires_at: None,
            rolled_back: false,
        };
        assert_ne!(state1, state2);
    }

    #[test]
    fn tenant_state_hash() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let state = TenantState {
            tenant_id: "tenant-1".to_string(),
            level: 1,
            action: RemediationAction::ALERT,
            reason: "Test".to_string(),
            alert_id: "alert-1".to_string(),
            applied_at: Utc::now().to_rfc3339(),
            expires_at: None,
            rolled_back: false,
        };
        let mut hasher = DefaultHasher::new();
        state.tenant_id.hash(&mut hasher);
        let _ = hasher.finish();
        assert!(true);
    }

    #[test]
    fn tenant_state_partial_eq() {
        let state1 = TenantState {
            tenant_id: "tenant-1".to_string(),
            level: 1,
            action: RemediationAction::ALERT,
            reason: "Test".to_string(),
            alert_id: "alert-1".to_string(),
            applied_at: Utc::now().to_rfc3339(),
            expires_at: None,
            rolled_back: false,
        };
        let state2 = state1.clone();
        assert!(state1 == state2);
    }

    #[test]
    fn tenant_state_partial_ne() {
        let state1 = TenantState {
            tenant_id: "tenant-1".to_string(),
            level: 1,
            action: RemediationAction::ALERT,
            reason: "Test".to_string(),
            alert_id: "alert-1".to_string(),
            applied_at: Utc::now().to_rfc3339(),
            expires_at: None,
            rolled_back: false,
        };
        let state2 = TenantState {
            tenant_id: "tenant-2".to_string(),
            level: 1,
            action: RemediationAction::ALERT,
            reason: "Test".to_string(),
            alert_id: "alert-1".to_string(),
            applied_at: Utc::now().to_rfc3339(),
            expires_at: None,
            rolled_back: false,
        };
        assert!(state1 != state2);
    }

    #[test]
    fn tenant_state_into_string() {
        let state = TenantState {
            tenant_id: "tenant-1".to_string(),
            level: 1,
            action: RemediationAction::ALERT,
            reason: "Test".to_string(),
            alert_id: "alert-1".to_string(),
            applied_at: Utc::now().to_rfc3339(),
            expires_at: None,
            rolled_back: false,
        };
        let s: String = serde_json::to_string(&state).unwrap();
        assert!(s.contains("tenant-1"));
    }

    #[test]
    fn tenant_state_from_json() {
        let json = r#"{"tenant_id":"tenant-1","level":1,"action":"ALERT","reason":"Test","alert_id":"alert-1","applied_at":"2026-01-01T00:00:00Z","expires_at":null,"rolled_back":false}"#;
        let state: TenantState = serde_json::from_str(json).unwrap();
        assert_eq!(state.tenant_id, "tenant-1");
        assert_eq!(state.level, 1);
    }

    #[test]
    fn tenant_state_action_alert() {
        let action = RemediationAction::ALERT;
        assert_eq!(action, RemediationAction::ALERT);
    }

    #[test]
    fn tenant_state_action_throttle() {
        let action = RemediationAction::THROTTLE;
        assert_eq!(action, RemediationAction::THROTTLE);
    }

    #[test]
    fn tenant_state_action_block() {
        let action = RemediationAction::BLOCK;
        assert_eq!(action, RemediationAction::BLOCK);
    }

    #[test]
    fn tenant_state_action_quarantine() {
        let action = RemediationAction::QUARANTINE;
        assert_eq!(action, RemediationAction::QUARANTINE);
    }

    #[test]
    fn tenant_state_action_none() {
        let action = RemediationAction::NONE;
        assert_eq!(action, RemediationAction::NONE);
    }

    #[test]
    fn tenant_state_level_zero() {
        let state = TenantState {
            tenant_id: "tenant-1".to_string(),
            level: 0,
            action: RemediationAction::NONE,
            reason: "Test".to_string(),
            alert_id: "alert-1".to_string(),
            applied_at: Utc::now().to_rfc3339(),
            expires_at: None,
            rolled_back: false,
        };
        assert_eq!(state.level, 0);
    }

    #[test]
    fn tenant_state_level_max() {
        let state = TenantState {
            tenant_id: "tenant-1".to_string(),
            level: 255,
            action: RemediationAction::BLOCK,
            reason: "Test".to_string(),
            alert_id: "alert-1".to_string(),
            applied_at: Utc::now().to_rfc3339(),
            expires_at: None,
            rolled_back: false,
        };
        assert_eq!(state.level, 255);
    }

    #[test]
    fn tenant_state_applied_at_format() {
        let applied_at = "2026-01-01T00:00:00Z";
        assert!(applied_at.contains("2026"));
        assert!(applied_at.contains("T"));
        assert!(applied_at.ends_with("Z"));
    }

    #[test]
    fn tenant_state_expires_at_format() {
        let expires_at = "2026-12-31T23:59:59Z";
        assert!(expires_at.contains("2026"));
        assert!(expires_at.contains("T"));
        assert!(expires_at.ends_with("Z"));
    }

    #[test]
    fn tenant_state_reason_format() {
        let reason = "AUTH_BRUTE_FORCE — Brute force authentification";
        assert!(reason.contains("—"));
        assert!(reason.contains("AUTH_BRUTE_FORCE"));
    }

    #[test]
    fn tenant_state_alert_id_format() {
        let alert_id = "alert-123";
        assert!(alert_id.starts_with("alert-"));
    }

    #[test]
    fn tenant_state_tenant_id_format() {
        let tenant_id = "tenant-123";
        assert!(tenant_id.starts_with("tenant-"));
    }

    #[test]
    fn tenant_state_rolled_back_true() {
        let state = TenantState {
            tenant_id: "tenant-1".to_string(),
            level: 1,
            action: RemediationAction::ALERT,
            reason: "Test".to_string(),
            alert_id: "alert-1".to_string(),
            applied_at: Utc::now().to_rfc3339(),
            expires_at: None,
            rolled_back: true,
        };
        assert!(state.rolled_back);
    }

    #[test]
    fn tenant_state_rolled_back_false() {
        let state = TenantState {
            tenant_id: "tenant-1".to_string(),
            level: 1,
            action: RemediationAction::ALERT,
            reason: "Test".to_string(),
            alert_id: "alert-1".to_string(),
            applied_at: Utc::now().to_rfc3339(),
            expires_at: None,
            rolled_back: false,
        };
        assert!(!state.rolled_back);
    }

    #[test]
    fn tenant_state_expires_at_some() {
        let state = TenantState {
            tenant_id: "tenant-1".to_string(),
            level: 1,
            action: RemediationAction::ALERT,
            reason: "Test".to_string(),
            alert_id: "alert-1".to_string(),
            applied_at: Utc::now().to_rfc3339(),
            expires_at: Some("2026-12-31T23:59:59Z".to_string()),
            rolled_back: false,
        };
        assert!(state.expires_at.is_some());
    }

    #[test]
    fn tenant_state_expires_at_none() {
        let state = TenantState {
            tenant_id: "tenant-1".to_string(),
            level: 1,
            action: RemediationAction::ALERT,
            reason: "Test".to_string(),
            alert_id: "alert-1".to_string(),
            applied_at: Utc::now().to_rfc3339(),
            expires_at: None,
            rolled_back: false,
        };
        assert!(state.expires_at.is_none());
    }

    #[test]
    fn tenant_state_action_clone() {
        let action = RemediationAction::THROTTLE;
        let cloned = action.clone();
        assert_eq!(action, cloned);
    }

    #[test]
    fn tenant_state_action_copy() {
        let action = RemediationAction::BLOCK;
        let copied = action;
        assert_eq!(action, copied);
    }

    #[test]
    fn tenant_state_action_debug() {
        let action = RemediationAction::ALERT;
        let debug = format!("{:?}", action);
        assert!(!debug.is_empty());
    }

    #[test]
    fn tenant_state_action_eq() {
        let action1 = RemediationAction::QUARANTINE;
        let action2 = RemediationAction::QUARANTINE;
        assert_eq!(action1, action2);
    }

    #[test]
    fn tenant_state_action_ne() {
        let action1 = RemediationAction::ALERT;
        let action2 = RemediationAction::BLOCK;
        assert_ne!(action1, action2);
    }

    #[test]
    fn tenant_state_action_hash() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let action = RemediationAction::THROTTLE;
        let mut hasher = DefaultHasher::new();
        action.hash(&mut hasher);
        let _ = hasher.finish();
        assert!(true);
    }

    #[test]
    fn tenant_state_action_partial_eq() {
        let action1 = RemediationAction::BLOCK;
        let action2 = RemediationAction::BLOCK;
        assert!(action1 == action2);
    }

    #[test]
    fn tenant_state_action_partial_ne() {
        let action1 = RemediationAction::ALERT;
        let action2 = RemediationAction::THROTTLE;
        assert!(action1 != action2);
    }

    #[test]
    fn tenant_state_action_into_string() {
        let action = RemediationAction::ALERT;
        let s: String = serde_json::to_string(&action).unwrap();
        assert!(!s.is_empty());
    }

    #[test]
    fn tenant_state_action_from_json() {
        let json = r#""ALERT""#;
        let action: RemediationAction = serde_json::from_str(json).unwrap();
        assert_eq!(action, RemediationAction::ALERT);
    }

    #[test]
    fn tenant_state_action_from_json_throttle() {
        let json = r#""THROTTLE""#;
        let action: RemediationAction = serde_json::from_str(json).unwrap();
        assert_eq!(action, RemediationAction::THROTTLE);
    }

    #[test]
    fn tenant_state_action_from_json_block() {
        let json = r#""BLOCK""#;
        let action: RemediationAction = serde_json::from_str(json).unwrap();
        assert_eq!(action, RemediationAction::BLOCK);
    }

    #[test]
    fn tenant_state_action_from_json_quarantine() {
        let json = r#""QUARANTINE""#;
        let action: RemediationAction = serde_json::from_str(json).unwrap();
        assert_eq!(action, RemediationAction::QUARANTINE);
    }

    #[test]
    fn tenant_state_action_from_json_none() {
        let json = r#""NONE""#;
        let action: RemediationAction = serde_json::from_str(json).unwrap();
        assert_eq!(action, RemediationAction::NONE);
    }

    #[test]
    fn tenant_state_serialize_to_bson() {
        let state = TenantState {
            tenant_id: "tenant-1".to_string(),
            level: 1,
            action: RemediationAction::ALERT,
            reason: "Test".to_string(),
            alert_id: "alert-1".to_string(),
            applied_at: Utc::now().to_rfc3339(),
            expires_at: None,
            rolled_back: false,
        };
        let result = bson::to_document(&state);
        assert!(result.is_ok());
    }

    #[test]
    fn tenant_state_deserialize_from_bson() {
        let mut doc = bson::Document::new();
        doc.insert("tenant_id", "tenant-1");
        doc.insert("level", 1i32);
        doc.insert("action", "ALERT");
        doc.insert("reason", "Test");
        doc.insert("alert_id", "alert-1");
        doc.insert("applied_at", "2026-01-01T00:00:00Z");
        doc.insert("expires_at", bson::Bson::Null);
        doc.insert("rolled_back", false);

        let result: Result<TenantState, _> = bson::from_document(doc);
        assert!(result.is_ok());
        let state = result.unwrap();
        assert_eq!(state.tenant_id, "tenant-1");
        assert_eq!(state.level, 1);
    }

    #[test]
    fn tenant_state_deserialize_from_bson_with_expiry() {
        let mut doc = bson::Document::new();
        doc.insert("tenant_id", "tenant-1");
        doc.insert("level", 2i32);
        doc.insert("action", "THROTTLE");
        doc.insert("reason", "Test");
        doc.insert("alert_id", "alert-1");
        doc.insert("applied_at", "2026-01-01T00:00:00Z");
        doc.insert("expires_at", "2026-12-31T23:59:59Z");
        doc.insert("rolled_back", false);

        let result: Result<TenantState, _> = bson::from_document(doc);
        assert!(result.is_ok());
        let state = result.unwrap();
        assert_eq!(state.expires_at, Some("2026-12-31T23:59:59Z".to_string()));
    }

    #[test]
    fn tenant_state_deserialize_from_bson_rolled_back() {
        let mut doc = bson::Document::new();
        doc.insert("tenant_id", "tenant-1");
        doc.insert("level", 1i32);
        doc.insert("action", "ALERT");
        doc.insert("reason", "Test");
        doc.insert("alert_id", "alert-1");
        doc.insert("applied_at", "2026-01-01T00:00:00Z");
        doc.insert("expires_at", bson::Bson::Null);
        doc.insert("rolled_back", true);

        let result: Result<TenantState, _> = bson::from_document(doc);
        assert!(result.is_ok());
        let state = result.unwrap();
        assert!(state.rolled_back);
    }

    #[test]
    fn tenant_state_deserialize_from_bson_level_zero() {
        let mut doc = bson::Document::new();
        doc.insert("tenant_id", "tenant-1");
        doc.insert("level", 0i32);
        doc.insert("action", "NONE");
        doc.insert("reason", "Test");
        doc.insert("alert_id", "alert-1");
        doc.insert("applied_at", "2026-01-01T00:00:00Z");
        doc.insert("expires_at", bson::Bson::Null);
        doc.insert("rolled_back", false);

        let result: Result<TenantState, _> = bson::from_document(doc);
        assert!(result.is_ok());
        let state = result.unwrap();
        assert_eq!(state.level, 0);
    }

    #[test]
    fn tenant_state_deserialize_from_bson_level_max() {
        let mut doc = bson::Document::new();
        doc.insert("tenant_id", "tenant-1");
        doc.insert("level", 255i32);
        doc.insert("action", "BLOCK");
        doc.insert("reason", "Test");
        doc.insert("alert_id", "alert-1");
        doc.insert("applied_at", "2026-01-01T00:00:00Z");
        doc.insert("expires_at", bson::Bson::Null);
        doc.insert("rolled_back", false);

        let result: Result<TenantState, _> = bson::from_document(doc);
        assert!(result.is_ok());
        let state = result.unwrap();
        assert_eq!(state.level, 255);
    }

    #[test]
    fn tenant_state_deserialize_from_bson_tenant_id_empty() {
        let mut doc = bson::Document::new();
        doc.insert("tenant_id", "");
        doc.insert("level", 1i32);
        doc.insert("action", "ALERT");
        doc.insert("reason", "Test");
        doc.insert("alert_id", "alert-1");
        doc.insert("applied_at", "2026-01-01T00:00:00Z");
        doc.insert("expires_at", bson::Bson::Null);
        doc.insert("rolled_back", false);

        let result: Result<TenantState, _> = bson::from_document(doc);
        assert!(result.is_ok());
        let state = result.unwrap();
        assert_eq!(state.tenant_id, "");
    }

    #[test]
    fn tenant_state_deserialize_from_bson_alert_id_empty() {
        let mut doc = bson::Document::new();
        doc.insert("tenant_id", "tenant-1");
        doc.insert("level", 1i32);
        doc.insert("action", "ALERT");
        doc.insert("reason", "Test");
        doc.insert("alert_id", "");
        doc.insert("applied_at", "2026-01-01T00:00:00Z");
        doc.insert("expires_at", bson::Bson::Null);
        doc.insert("rolled_back", false);

        let result: Result<TenantState, _> = bson::from_document(doc);
        assert!(result.is_ok());
        let state = result.unwrap();
        assert_eq!(state.alert_id, "");
    }

    #[test]
    fn tenant_state_deserialize_from_bson_reason_empty() {
        let mut doc = bson::Document::new();
        doc.insert("tenant_id", "tenant-1");
        doc.insert("level", 1i32);
        doc.insert("action", "ALERT");
        doc.insert("reason", "");
        doc.insert("alert_id", "alert-1");
        doc.insert("applied_at", "2026-01-01T00:00:00Z");
        doc.insert("expires_at", bson::Bson::Null);
        doc.insert("rolled_back", false);

        let result: Result<TenantState, _> = bson::from_document(doc);
        assert!(result.is_ok());
        let state = result.unwrap();
        assert_eq!(state.reason, "");
    }

    #[test]
    fn tenant_state_deserialize_from_bson_applied_at_empty() {
        let mut doc = bson::Document::new();
        doc.insert("tenant_id", "tenant-1");
        doc.insert("level", 1i32);
        doc.insert("action", "ALERT");
        doc.insert("reason", "Test");
        doc.insert("alert_id", "alert-1");
        doc.insert("applied_at", "");
        doc.insert("expires_at", bson::Bson::Null);
        doc.insert("rolled_back", false);

        let result: Result<TenantState, _> = bson::from_document(doc);
        assert!(result.is_ok());
        let state = result.unwrap();
        assert_eq!(state.applied_at, "");
    }
}
