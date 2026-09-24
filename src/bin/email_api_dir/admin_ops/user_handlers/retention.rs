#![allow(unused_imports, dead_code)]
use super::super::*; // inherit all imports from admin_ops/mod.rs

pub(crate) const RETENTION_CONFIG_COLLECTION: &str = "retention_policy_config";
pub(crate) const RETENTION_AUDIT_COLLECTION: &str = "retention_audit_log";
pub(crate) const EMAILS_COLLECTION: &str = "emails";

/// Best-effort audit log insert — never fails, logs stderr on Mongo error.
pub(crate) async fn log_retention_action(
    mongo: &mongodb::Client,
    action: &str,
    user_id: &str,
    retention_days: i64,
    emails_purged: i64,
    oldest_retained: Option<String>,
    note: Option<String>,
) {
    let entry = RetentionAuditEntry {
        id: Uuid::new_v4().to_string(),
        at: now_iso(),
        action: action.to_string(),
        user_id: user_id.to_string(),
        retention_days,
        emails_purged,
        oldest_retained,
        note,
    };
    let coll = mongo
        .database(&mongo_db_name())
        .collection::<RetentionAuditEntry>(RETENTION_AUDIT_COLLECTION);
    if let Err(e) = coll.insert_one(&entry).await {
        eprintln!("log_retention_action: insert error: {}", e);
    }
}

/// Find the retention config for a given user.
pub(crate) async fn get_retention_config(
    mongo: &mongodb::Client,
    user_id: &str,
) -> Option<RetentionPolicyConfig> {
    let coll = mongo
        .database(&mongo_db_name())
        .collection::<RetentionPolicyConfig>(RETENTION_CONFIG_COLLECTION);
    coll.find_one(doc! { "userId": user_id })
        .await
        .unwrap_or_default()
}

/// Upsert a retention config (keyed by user_id).
pub(crate) async fn save_retention_config(
    mongo: &mongodb::Client,
    config: RetentionPolicyConfig,
) {
    let coll = mongo
        .database(&mongo_db_name())
        .collection::<RetentionPolicyConfig>(RETENTION_CONFIG_COLLECTION);
    let filter = doc! { "userId": &config.user_id };
    let update = doc! {
        "$set": {
            "userId": &config.user_id,
            "retentionDays": config.retention_days,
            "autoPurgeEnabled": config.auto_purge_enabled,
            "updatedAt": &config.updated_at,
        }
    };
    if let Err(e) = coll.update_one(filter, update).upsert(true).await {
        eprintln!("save_retention_config: upsert error: {}", e);
    }
}

/// Delete emails from the `emails` collection whose `internal_date` is older
/// than `now - retention_days`. Returns the count of purged documents.
/// If `retention_days` is 0, no emails are purged (never-purge policy).
pub(crate) async fn purge_expired_metadata(
    mongo: &mongodb::Client,
    user_id: &str,
    retention_days: i64,
) -> i64 {
    if retention_days <= 0 {
        return 0;
    }
    let coll = mongo
        .database(&mongo_db_name())
        .collection::<mongodb::bson::Document>(EMAILS_COLLECTION);
    let cutoff = Utc::now() - chrono::Duration::days(retention_days);
    let cutoff_bson = mongodb::bson::DateTime::from_millis(cutoff.timestamp_millis());
    let filter = doc! {
        "userId": user_id,
        "internalDate": { "$lt": cutoff_bson }
    };
    match coll.delete_many(filter).await {
        Ok(result) => result.deleted_count as i64,
        Err(e) => {
            eprintln!("purge_expired_metadata: delete error: {}", e);
            0
        }
    }
}

/// Iterate all configs where auto_purge_enabled == true and purge expired
/// metadata for each user. Returns the total count of purged emails.
pub(crate) async fn run_auto_purge_all(mongo: &mongodb::Client) -> i64 {
    let coll = mongo
        .database(&mongo_db_name())
        .collection::<RetentionPolicyConfig>(RETENTION_CONFIG_COLLECTION);
    let filter = doc! { "autoPurgeEnabled": true };
    let mut total_purged: i64 = 0;
    let mut cursor = match coll.find(filter).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("run_auto_purge_all: find error: {}", e);
            return 0;
        }
    };
    // Collect configs first to avoid holding the cursor across awaits.
    let configs: Vec<RetentionPolicyConfig> = cursor.try_collect().await.unwrap_or_default();
    for config in configs {
        let count = purge_expired_metadata(mongo, &config.user_id, config.retention_days).await;
        if count > 0 {
            log_retention_action(
                mongo,
                "purge",
                &config.user_id,
                config.retention_days,
                count,
                None,
                Some("auto-purge".to_string()),
            )
            .await;
        }
        total_purged += count;
    }
    total_purged
}

// ── HTTP Handlers ───────────────────────────────────────────────────────────

/// GET /api/admin/retention-policy — return config for the authenticated user.
pub(crate) async fn api_get_retention_policy(
    req: HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let actor = match admin_auth::require_admin(&req, &mongo, &mongo_db_name()).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    let config = get_retention_config(&mongo, &actor.user_id).await;
    match config {
        Some(c) => HttpResponse::Ok().json(serde_json::json!({
            "generatedAt": now_iso(),
            "config": c,
        })),
        None => HttpResponse::Ok().json(serde_json::json!({
            "generatedAt": now_iso(),
            "config": null,
            "message": "No retention policy configured for this user",
        })),
    }
}

/// PUT /api/admin/retention-policy — update config for the authenticated user.
pub(crate) async fn api_update_retention_policy(
    req: HttpRequest,
    body: web::Json<RetentionPolicyConfig>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let actor = match admin_auth::require_admin(&req, &mongo, &mongo_db_name()).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    let mut config = body.into_inner();
    // Validate retention_days >= 0
    if config.retention_days < 0 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "message": "retentionDays must be >= 0",
        }));
    }
    config.user_id = actor.user_id.clone();
    config.updated_at = now_iso();
    save_retention_config(&mongo, config.clone()).await;
    log_retention_action(
        &mongo,
        "config_update",
        &actor.user_id,
        config.retention_days,
        0,
        None,
        Some("Retention policy updated".to_string()),
    )
    .await;
    HttpResponse::Ok().json(serde_json::json!({
        "generatedAt": now_iso(),
        "config": config,
    }))
}

/// POST /api/admin/retention-policy/purge — trigger immediate purge for the user.
pub(crate) async fn api_trigger_purge(
    req: HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let actor = match admin_auth::require_admin(&req, &mongo, &mongo_db_name()).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    let config = match get_retention_config(&mongo, &actor.user_id).await {
        Some(c) => c,
        None => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "message": "No retention policy configured for this user",
            }));
        }
    };
    if config.retention_days <= 0 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "message": "Retention days is 0 (never purge); update policy first",
        }));
    }
    let count = purge_expired_metadata(&mongo, &actor.user_id, config.retention_days).await;
    log_retention_action(
        &mongo,
        "purge",
        &actor.user_id,
        config.retention_days,
        count,
        None,
        Some("Manual purge triggered".to_string()),
    )
    .await;
    HttpResponse::Ok().json(serde_json::json!({
        "generatedAt": now_iso(),
        "emailsPurged": count,
    }))
}

/// GET /api/admin/retention-audit — return retention audit entries for the user.
pub(crate) async fn api_retention_audit_log(
    req: HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let actor = match admin_auth::require_admin(&req, &mongo, &mongo_db_name()).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    let coll = mongo
        .database(&mongo_db_name())
        .collection::<RetentionAuditEntry>(RETENTION_AUDIT_COLLECTION);
    let filter = doc! { "userId": &actor.user_id };
    match coll.find(filter).sort(doc! { "at": -1 }).limit(200).await {
        Ok(cursor) => {
            let entries = cursor
                .try_collect::<Vec<RetentionAuditEntry>>()
                .await
                .unwrap_or_default();
            HttpResponse::Ok().json(serde_json::json!({
                "generatedAt": now_iso(),
                "entries": entries,
            }))
        }
        Err(e) => {
            eprintln!("retention_audit_log query error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to load retention audit log" }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retention_policy_config_serializes_camelcase() {
        let config = RetentionPolicyConfig {
            user_id: "user-42".into(),
            retention_days: 365,
            auto_purge_enabled: false,
            updated_at: "2026-06-15T12:00:00Z".into(),
        };
        let json = serde_json::to_value(&config).unwrap();
        assert_eq!(json["userId"], "user-42");
        assert_eq!(json["retentionDays"], 365);
        assert_eq!(json["autoPurgeEnabled"], false);
        assert_eq!(json["updatedAt"], "2026-06-15T12:00:00Z");
    }

    #[test]
    fn retention_audit_entry_serializes_camelcase() {
        let entry = RetentionAuditEntry {
            id: "audit-99".into(),
            at: "2026-01-01T00:00:00Z".into(),
            action: "policy_eval".into(),
            user_id: "user-7".into(),
            retention_days: 30,
            emails_purged: 0,
            oldest_retained: None,
            note: Some("evaluated".into()),
        };
        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(json["id"], "audit-99");
        assert_eq!(json["action"], "policy_eval");
        assert_eq!(json["userId"], "user-7");
        assert_eq!(json["retentionDays"], 30);
        assert_eq!(json["emailsPurged"], 0);
        assert!(json["oldestRetained"].is_null());
        assert_eq!(json["note"], "evaluated");
    }

    #[test]
    fn retention_audit_entry_roundtrip_preserves_all_fields() {
        let entry = RetentionAuditEntry {
            id: "roundtrip-1".into(),
            at: "2026-03-01T08:30:00Z".into(),
            action: "purge".into(),
            user_id: "user-xyz".into(),
            retention_days: 90,
            emails_purged: 150,
            oldest_retained: Some("2025-12-01T00:00:00Z".into()),
            note: Some("auto-purge cycle".into()),
        };
        let json = serde_json::to_value(&entry).unwrap();
        let parsed: RetentionAuditEntry = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.id, entry.id);
        assert_eq!(parsed.at, entry.at);
        assert_eq!(parsed.action, entry.action);
        assert_eq!(parsed.user_id, entry.user_id);
        assert_eq!(parsed.retention_days, entry.retention_days);
        assert_eq!(parsed.emails_purged, entry.emails_purged);
        assert_eq!(parsed.oldest_retained, entry.oldest_retained);
        assert_eq!(parsed.note, entry.note);
    }
}
