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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_audit_coll_name() {
        assert_eq!(ADMIN_AUDIT_COLL, "admin_audit_log");
    }

    #[test]
    fn admin_audit_entry_fields() {
        let entry = AdminAuditEntry {
            id: "test-id".to_string(),
            at: "2024-01-01T00:00:00Z".to_string(),
            actor_id: "actor1".to_string(),
            actor_email: "actor@test.com".to_string(),
            action: "user.create".to_string(),
            target_kind: "admin_user".to_string(),
            target_id: "user1".to_string(),
            note: Some("test note".to_string()),
            diff: None,
        };
        assert_eq!(entry.id, "test-id");
        assert_eq!(entry.actor_id, "actor1");
        assert_eq!(entry.action, "user.create");
        assert_eq!(entry.target_kind, "admin_user");
        assert_eq!(entry.note, Some("test note".to_string()));
        assert!(entry.diff.is_none());
    }

    #[test]
    fn admin_audit_query_fields() {
        let query = AdminAuditQuery {
            target: Some("user1".to_string()),
            actor: Some("actor1".to_string()),
            action: Some("user.create".to_string()),
            limit: Some(50),
        };
        assert_eq!(query.target, Some("user1".to_string()));
        assert_eq!(query.actor, Some("actor1".to_string()));
        assert_eq!(query.action, Some("user.create".to_string()));
        assert_eq!(query.limit, Some(50));
    }

    #[test]
    fn admin_audit_query_defaults() {
        let query = AdminAuditQuery {
            target: None,
            actor: None,
            action: None,
            limit: None,
        };
        assert!(query.target.is_none());
        assert!(query.actor.is_none());
        assert!(query.action.is_none());
        assert!(query.limit.is_none());
    }
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

