#![allow(unused_imports, dead_code)]
use super::super::*;  // inherit all imports from admin_ops/mod.rs

pub(crate) const ADMIN_AUDIT_COLL: &str = "admin_audit_log";

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AdminAuditEntry {
    id: String,
    at: String,
    actor_id: String,
    actor_email: String,
    action: String,
    target_kind: String,
    target_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    diff: Option<serde_json::Value>,
}

/// Best-effort — n'échoue jamais, log stderr en cas de problème Mongo.
pub(crate) async fn log_admin_action(
    mongo: &mongodb::Client,
    actor: &admin_auth::AuthUser,
    action: &str,
    target_kind: &str,
    target_id: &str,
    note: Option<String>,
    diff: Option<serde_json::Value>,
) {
    let entry = AdminAuditEntry {
        id: Uuid::new_v4().to_string(),
        at: now_iso(),
        actor_id: actor.user_id.clone(),
        actor_email: actor.email.clone(),
        action: action.to_string(),
        target_kind: target_kind.to_string(),
        target_id: target_id.to_string(),
        note,
        diff,
    };
    let coll = mongo
        .database(&mongo_db_name())
        .collection::<AdminAuditEntry>(ADMIN_AUDIT_COLL);
    if let Err(e) = coll.insert_one(&entry).await {
        eprintln!("log_admin_action: insert error: {}", e);
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct AdminAuditQuery {
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    actor: Option<String>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    limit: Option<i64>,
}

/// GET /api/admin/audit-log
pub(crate) async fn api_admin_audit_log(
    req: HttpRequest,
    query: web::Query<AdminAuditQuery>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if let Err(resp) = admin_auth::require_admin(&req, &mongo, &mongo_db_name()).await {
        return resp;
    }
    let coll = mongo
        .database(&mongo_db_name())
        .collection::<AdminAuditEntry>(ADMIN_AUDIT_COLL);
    let mut filter = mongodb::bson::Document::new();
    if let Some(t) = &query.target {
        let t = t.trim();
        if !t.is_empty() {
            filter.insert("targetId", t);
        }
    }
    if let Some(a) = &query.actor {
        let a = a.trim();
        if !a.is_empty() {
            filter.insert("actorId", a);
        }
    }
    if let Some(a) = &query.action {
        let a = a.trim();
        if !a.is_empty() {
            filter.insert("action", a);
        }
    }
    let limit = query.limit.unwrap_or(200).clamp(1, 1000);
    match coll
        .find(filter)
        .sort(doc! { "at": -1 })
        .limit(limit)
        .await
    {
        Ok(cursor) => {
            let entries = cursor
                .try_collect::<Vec<AdminAuditEntry>>()
                .await
                .unwrap_or_default();
            HttpResponse::Ok().json(serde_json::json!({
                "generatedAt": now_iso(),
                "entries": entries,
            }))
        }
        Err(e) => {
            eprintln!("audit_log query error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to load audit log" }))
        }
    }
}

