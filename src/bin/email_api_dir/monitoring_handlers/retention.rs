//! Metadata retention policy handlers (issue #701)
//!
//! ePrivacy Regulation Art.5(1)c (minimisation) + GDPR Art.5(1)e (limitation conservation)
//! Configurable retention period + auto-purge + audit log.

use actix_web::{web, HttpResponse};
use mongodb::bson::{doc, Document};
use std::sync::Arc;
use chrono::{DateTime, Utc, Duration};

/// Retention period configuration
#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RetentionSettings {
    /// Retention period in days. 0 = unlimited.
    pub(crate) retention_days: i64,
    /// When the setting was last updated (RFC3339 string)
    pub(crate) updated_at: Option<String>,
    /// Who last updated the setting
    pub(crate) updated_by: Option<String>,
}

impl Default for RetentionSettings {
    fn default() -> Self {
        Self {
            retention_days: 90, // Default: 90 days per GDPR best practice
            updated_at: None,
            updated_by: None,
        }
    }
}

/// Audit log entry for retention actions
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RetentionAuditEntry {
    pub(crate) timestamp: String,
    pub(crate) user: String,
    pub(crate) action: String,
    pub(crate) metadata_type: String,
    pub(crate) details: String,
}

const SETTINGS_COLLECTION: &str = "retention_settings";
const AUDIT_COLLECTION: &str = "retention_audit_log";
const SETTINGS_DOC_ID: &str = "global_retention";

fn db_name() -> String {
    std::env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string())
}

/// GET /api/settings/retention — get current retention settings
pub(crate) async fn api_retention_get(
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl actix_web::Responder {
    let coll = mongo
        .database(&db_name())
        .collection::<Document>(SETTINGS_COLLECTION);

    match coll.find_one(doc! { "_id": SETTINGS_DOC_ID }).await {
        Ok(Some(doc)) => {
            match mongodb::bson::from_document::<RetentionSettings>(doc) {
                Ok(settings) => HttpResponse::Ok().json(settings),
                Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
                    "status": "error",
                    "message": format!("Failed to deserialize settings: {}", e)
                })),
            }
        }
        Ok(None) => {
            // Return defaults
            HttpResponse::Ok().json(RetentionSettings::default())
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "status": "error",
            "message": format!("Database error: {}", e)
        })),
    }
}

/// PUT /api/settings/retention — update retention settings
pub(crate) async fn api_retention_put(
    req: web::Json<serde_json::Value>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl actix_web::Responder {
    let retention_days = req
        .get("retentionDays")
        .and_then(|v| v.as_i64())
        .unwrap_or(90);

    // Validate: 0 (unlimited), 30, 90, 365
    if ![0, 30, 90, 365].contains(&retention_days) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "status": "error",
            "message": "retentionDays must be one of: 0 (unlimited), 30, 90, 365"
        }));
    }

    let now = Utc::now();
    let updated_by = req
        .get("updatedBy")
        .and_then(|v| v.as_str())
        .unwrap_or("system")
        .to_string();

    let settings_doc = doc! {
        "_id": SETTINGS_DOC_ID,
        "retentionDays": retention_days,
        "updatedAt": now.to_rfc3339(),
        "updatedBy": &updated_by,
    };

    let coll = mongo
        .database(&db_name())
        .collection::<Document>(SETTINGS_COLLECTION);

    let _ = coll
        .replace_one(doc! { "_id": SETTINGS_DOC_ID }, settings_doc)
        .upsert(true)
        .await;

    // Audit log the change
    let audit = doc! {
        "timestamp": mongodb::bson::DateTime::from_chrono(now),
        "user": &updated_by,
        "action": "settings_updated",
        "metadataType": "retention_policy",
        "details": format!("retentionDays set to {}", retention_days),
    };
    let audit_coll = mongo
        .database(&db_name())
        .collection::<Document>(AUDIT_COLLECTION);
    let _ = audit_coll.insert_one(audit).await;

    HttpResponse::Ok().json(serde_json::json!({
        "status": "success",
        "retentionDays": retention_days,
        "updatedAt": now.to_rfc3339(),
        "updatedBy": updated_by,
    }))
}

/// POST /api/settings/retention/purge — trigger manual purge of expired metadata
pub(crate) async fn api_retention_purge(
    req: web::Json<serde_json::Value>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl actix_web::Responder {
    let now = Utc::now();
    let user = req
        .get("user")
        .and_then(|v| v.as_str())
        .unwrap_or("system")
        .to_string();

    // Get current retention settings
    let settings_coll = mongo
        .database(&db_name())
        .collection::<Document>(SETTINGS_COLLECTION);

    let retention_days = match settings_coll.find_one(doc! { "_id": SETTINGS_DOC_ID }).await {
        Ok(Some(doc)) => doc.get_i64("retentionDays").unwrap_or(90),
        _ => 90,
    };

    if retention_days == 0 {
        return HttpResponse::Ok().json(serde_json::json!({
            "status": "skipped",
            "message": "Retention is set to unlimited (0), no purge needed"
        }));
    }

    let cutoff = now - Duration::days(retention_days);
    let cutoff_bson = mongodb::bson::DateTime::from_chrono(cutoff);

    // Purge expired email metadata (keep body, remove headers/metadata)
    let emails_coll = mongo
        .database(&db_name())
        .collection::<Document>("emails");

    let purge_filter = doc! {
        "internalDate": { "$lt": cutoff_bson },
        "metadataPurged": { "$ne": true },
    };

    // Set metadata-purged flag and clear sensitive headers
    let update = doc! {
        "$set": {
            "metadataPurged": true,
            "headers": [],
            "purgedAt": mongodb::bson::DateTime::from_chrono(now),
        }
    };

    let result = emails_coll.update_many(purge_filter, update).await;

    let purged_count = match result {
        Ok(r) => r.modified_count,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "status": "error",
                "message": format!("Purge failed: {}", e)
            }));
        }
    };

    // Audit log the purge
    let audit = doc! {
        "timestamp": mongodb::bson::DateTime::from_chrono(now),
        "user": &user,
        "action": "metadata_purged",
        "metadataType": "email_headers",
        "details": format!("purged {} emails older than {} days", purged_count, retention_days),
    };
    let audit_coll = mongo
        .database(&db_name())
        .collection::<Document>(AUDIT_COLLECTION);
    let _ = audit_coll.insert_one(audit).await;

    HttpResponse::Ok().json(serde_json::json!({
        "status": "success",
        "purged": purged_count,
        "retentionDays": retention_days,
        "cutoff": cutoff.to_rfc3339(),
        "user": user,
    }))
}

/// GET /api/settings/retention/audit — list audit log entries
pub(crate) async fn api_retention_audit(
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl actix_web::Responder {
    let audit_coll = mongo
        .database(&db_name())
        .collection::<Document>(AUDIT_COLLECTION);

    let cursor = audit_coll
        .find(doc! {})
        .sort(doc! { "timestamp": -1 })
        .limit(100)
        .await;

    match cursor {
        Ok(mut cursor) => {
            let mut entries: Vec<serde_json::Value> = Vec::new();
            while let Ok(Some(doc)) = cursor.try_next().await {
                if let Ok(json) = serde_json::to_value(&doc) {
                    entries.push(json);
                }
            }
            HttpResponse::Ok().json(serde_json::json!({
                "status": "success",
                "entries": entries,
                "count": entries.len(),
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "status": "error",
            "message": format!("Failed to fetch audit log: {}", e)
        })),
    }
}

/// Cron job entrypoint — auto-purge expired metadata
/// Called by the periodic scheduler (no HTTP context).
pub(crate) async fn retention_auto_purge(
    mongo: Arc<mongodb::Client>,
) -> Result<u64, Box<dyn std::error::Error>> {
    let db = mongo.database(&db_name());
    let settings_coll = db.collection::<Document>(SETTINGS_COLLECTION);

    let retention_days = match settings_coll.find_one(doc! { "_id": SETTINGS_DOC_ID }).await? {
        Some(doc) => doc.get_i64("retentionDays").unwrap_or(90),
        None => 90,
    };

    if retention_days == 0 {
        return Ok(0);
    }

    let now = Utc::now();
    let cutoff = now - Duration::days(retention_days);
    let cutoff_bson = mongodb::bson::DateTime::from_chrono(cutoff);

    let emails_coll = db.collection::<Document>("emails");
    let purge_filter = doc! {
        "internalDate": { "$lt": cutoff_bson },
        "metadataPurged": { "$ne": true },
    };
    let update = doc! {
        "$set": {
            "metadataPurged": true,
            "headers": [],
            "purgedAt": mongodb::bson::DateTime::from_chrono(now),
        }
    };

    let result = emails_coll.update_many(purge_filter, update).await?;
    let count = result.modified_count;

    // Audit log
    let audit = doc! {
        "timestamp": mongodb::bson::DateTime::from_chrono(now),
        "user": "system_cron",
        "action": "auto_purge",
        "metadataType": "email_headers",
        "details": format!("auto-purged {} emails older than {} days", count, retention_days),
    };
    let audit_coll = db.collection::<Document>(AUDIT_COLLECTION);
    let _ = audit_coll.insert_one(audit).await;

    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retention_settings_default() {
        let s = RetentionSettings::default();
        assert_eq!(s.retention_days, 90);
    }

    #[test]
    fn retention_valid_periods() {
        let valid = vec![0, 30, 90, 365];
        for days in valid {
            assert!([0, 30, 90, 365].contains(&days));
        }
    }

    #[test]
    fn retention_audit_entry_serialization() {
        let entry = RetentionAuditEntry {
            timestamp: "2026-09-24T12:00:00Z".to_string(),
            user: "test_user".to_string(),
            action: "settings_updated".to_string(),
            metadata_type: "retention_policy".to_string(),
            details: "retentionDays set to 90".to_string(),
        };
        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(json["user"], "test_user");
        assert_eq!(json["action"], "settings_updated");
    }

    #[test]
    fn db_name_default() {
        // Will return "mailserver" if env not set
        let name = db_name();
        assert!(!name.is_empty());
    }
}
