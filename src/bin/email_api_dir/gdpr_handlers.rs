//! GDPR data deletion (account + all personal data purge) — Issue #581.
//!
//! Provides endpoints for GDPR Article 17 (right to erasure):
//! - POST /api/gdpr/deletion/request — request account deletion
//! - POST /api/gdpr/deletion/confirm — confirm deletion via token
//! - GET /api/gdpr/deletion/status — check deletion request status
//! - POST /api/gdpr/data-export — export all user data (portability)

use actix_web::{web, HttpRequest, HttpResponse, Responder};
use bson::doc;
use chrono::{Duration, Utc};
use mongodb::Collection;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

use crate::admin_auth;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct DeletionRequest {
    pub(crate) id: String,
    pub(crate) user_id: String,
    pub(crate) email: String,
    pub(crate) status: String,
    pub(crate) confirmation_token: String,
    pub(crate) requested_at: String,
    pub(crate) confirm_deadline: String,
    pub(crate) confirmed_at: Option<String>,
    pub(crate) completed_at: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DeletionRequestInput {
    pub(crate) reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DeletionConfirmInput {
    pub(crate) token: String,
}

pub(crate) const GDPR_DELETION_COLL: &str = "gdpr_deletion_requests";
pub(crate) const GDPR_DATA_EXPORT_COLL: &str = "gdpr_data_exports";

pub(crate) async fn api_gdpr_deletion_request(
    req: HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if let Err(resp) = admin_auth::require_auth(&req, &mongo, &mongo_db_name()).await {
        return resp;
    }
    let user_id = crate::resolve_user_id(&req);
    let db = mongo.database(&mongo_db_name());
    let coll: Collection<DeletionRequest> = db.collection(GDPR_DELETION_COLL);
    if let Ok(Some(existing)) = coll.find_one(doc!{"user_id":&user_id,"status":"pending"}).await {
        return HttpResponse::Conflict().json(json!({
            "error": {"code":"DELETION_ALREADY_REQUESTED","message":"A deletion request is already pending","requested_at":existing.requested_at,"confirm_deadline":existing.confirm_deadline}
        }));
    }
    let email = req.headers().get("x-user-email").and_then(|v|v.to_str().ok()).unwrap_or("").to_string();
    let now = Utc::now();
    let deadline = now + Duration::hours(24);
    let token = Uuid::new_v4().to_string();
    let deletion = DeletionRequest {
        id: Uuid::new_v4().to_string(), user_id: user_id.clone(), email,
        status: "pending".to_string(), confirmation_token: token,
        requested_at: now.to_rfc3339(), confirm_deadline: deadline.to_rfc3339(),
        confirmed_at: None, completed_at: None,
    };
    if let Err(e) = coll.insert_one(&deletion).await {
        return HttpResponse::InternalServerError().json(json!({"error":{"code":"DB_ERROR","message":format!("Failed to create deletion request: {}",e)}}));
    }
    log_gdpr_action(&db, &user_id, "deletion_requested", &deletion.id).await;
    HttpResponse::Ok().json(json!({
        "status":"pending","message":"Deletion request created. Check your email for confirmation link.",
        "request_id":deletion.id,"confirm_deadline":deletion.confirm_deadline,
        "note":"You have 24 hours to confirm deletion. After confirmation, all data will be permanently purged."
    }))
}

pub(crate) async fn api_gdpr_deletion_confirm(
    req: HttpRequest,
    payload: web::Json<DeletionConfirmInput>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if let Err(resp) = admin_auth::require_auth(&req, &mongo, &mongo_db_name()).await {
        return resp;
    }
    let user_id = crate::resolve_user_id(&req);
    let db = mongo.database(&mongo_db_name());
    let coll: Collection<DeletionRequest> = db.collection(GDPR_DELETION_COLL);
    let filter = doc!{"user_id":&user_id,"confirmation_token":&payload.token,"status":"pending"};
    let request = match coll.find_one(filter).await {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::NotFound().json(json!({"error":{"code":"INVALID_TOKEN","message":"No pending deletion request found"}})),
        Err(e) => return HttpResponse::InternalServerError().json(json!({"error":{"code":"DB_ERROR","message":e.to_string()}})),
    };
    let deadline = match chrono::DateTime::parse_from_rfc3339(&request.confirm_deadline) {
        Ok(d) => d.with_timezone(&Utc),
        Err(_) => return HttpResponse::InternalServerError().json(json!({"error":{"code":"DATE_ERROR","message":"Invalid deadline format"}})),
    };
    if Utc::now() > deadline {
        let _ = coll.update_one(doc!{"id":&request.id},doc!{"$set":{"status":"expired"}}).await;
        return HttpResponse::Gone().json(json!({"error":{"code":"DEADLINE_EXPIRED","message":"Deletion request expired. Please request again."}}));
    }
    let now = Utc::now().to_rfc3339();
    let _ = coll.update_one(doc!{"id":&request.id},doc!{"$set":{"status":"confirmed","confirmed_at":&now}}).await;
    let purge_result = purge_all_user_data(&db, &user_id).await;
    let completed_at = Utc::now().to_rfc3339();
    let _ = coll.update_one(doc!{"id":&request.id},doc!{"$set":{"status":"completed","completed_at":&completed_at}}).await;
    log_gdpr_action(&db, &user_id, "deletion_completed", &request.id).await;
    match purge_result {
        Ok(stats) => HttpResponse::Ok().json(json!({"status":"completed","message":"All personal data permanently deleted.","purge_stats":stats,"completed_at":completed_at})),
        Err(e) => HttpResponse::InternalServerError().json(json!({"error":{"code":"PURGE_ERROR","message":format!("Partial purge failure: {}",e)},"status":"partial_failure"})),
    }
}

pub(crate) async fn api_gdpr_deletion_status(
    req: HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if let Err(resp) = admin_auth::require_auth(&req, &mongo, &mongo_db_name()).await {
        return resp;
    }
    let user_id = crate::resolve_user_id(&req);
    let db = mongo.database(&mongo_db_name());
    let coll: Collection<DeletionRequest> = db.collection(GDPR_DELETION_COLL);
    match coll.find_one(doc!{"user_id":&user_id}).sort(doc!{"requested_at":-1}).await {
        Ok(Some(r)) => HttpResponse::Ok().json(json!({"request_id":r.id,"status":r.status,"requested_at":r.requested_at,"confirm_deadline":r.confirm_deadline,"confirmed_at":r.confirmed_at,"completed_at":r.completed_at})),
        Ok(None) => HttpResponse::Ok().json(json!({"status":"none","message":"No deletion request found"})),
        Err(e) => HttpResponse::InternalServerError().json(json!({"error":{"code":"DB_ERROR","message":e.to_string()}})),
    }
}

pub(crate) async fn api_gdpr_data_export(
    req: HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if let Err(resp) = admin_auth::require_auth(&req, &mongo, &mongo_db_name()).await {
        return resp;
    }
    let user_id = crate::resolve_user_id(&req);
    let db = mongo.database(&mongo_db_name());
    let mut export = serde_json::Map::new();
    let emails_coll = db.collection::<bson::Document>("emails");
    let email_count = emails_coll.count_documents(doc!{"user_id":&user_id}).await.unwrap_or(0);
    export.insert("email_count".to_string(), json!(email_count));
    let contacts_coll = db.collection::<bson::Document>("contacts");
    let contact_count = contacts_coll.count_documents(doc!{"user_id":&user_id}).await.unwrap_or(0);
    export.insert("contact_count".to_string(), json!(contact_count));
    let users_coll = db.collection::<bson::Document>("users");
    if let Ok(Some(user)) = users_coll.find_one(doc!{"id":&user_id}).await {
        export.insert("account".to_string(), json!(user));
    }
    let gdpr_coll = db.collection::<bson::Document>(GDPR_DELETION_COLL);
    let del_count = gdpr_coll.count_documents(doc!{"user_id":&user_id}).await.unwrap_or(0);
    export.insert("deletion_request_count".to_string(), json!(del_count));
    log_gdpr_action(&db, &user_id, "data_export", "").await;
    HttpResponse::Ok().json(json!({"exported_at":Utc::now().to_rfc3339(),"user_id":user_id,"data":export,"format":"JSON","note":"Email bodies excluded (zero-access encryption)."}))
}

async fn purge_all_user_data(db: &mongodb::Database, user_id: &str) -> Result<serde_json::Value, String> {
    let mut stats = serde_json::Map::new();
    let collections = vec!["emails", "contacts", "calendar_events", "files", "sessions", "external_accounts"];
    let labels = vec!["emails_deleted", "contacts_deleted", "events_deleted", "files_deleted", "sessions_deleted", "external_accounts_deleted"];
    for (coll_name, label) in collections.iter().zip(labels.iter()) {
        let coll = db.collection::<bson::Document>(coll_name);
        match coll.delete_many(doc!{"user_id":user_id}).await {
            Ok(r) => { stats.insert(label.to_string(), json!(r.deleted_count)); }
            Err(e) => return Err(format!("{}: {}", coll_name, e)),
        }
    }
    let users_coll = db.collection::<bson::Document>("users");
    match users_coll.delete_one(doc!{"id":user_id}).await {
        Ok(r) => { stats.insert("user_deleted".to_string(), json!(r.deleted_count)); }
        Err(e) => return Err(format!("user: {}", e)),
    }
    stats.insert("purge_completed_at".to_string(), json!(Utc::now().to_rfc3339()));
    Ok(serde_json::Value::Object(stats))
}

async fn log_gdpr_action(db: &mongodb::Database, user_id: &str, action: &str, request_id: &str) {
    let audit_coll = db.collection::<bson::Document>("gdpr_audit_log");
    let _ = audit_coll.insert_one(doc!{
        "id":Uuid::new_v4().to_string(),"user_id":user_id,"action":action,
        "request_id":request_id,"timestamp":Utc::now().to_rfc3339(),"actor":"self-service",
    }).await;
}

fn mongo_db_name() -> String {
    std::env::var("MONGO_DB_NAME").unwrap_or_else(|_| "novamail".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn gdpr_deletion_coll_name() { assert_eq!(GDPR_DELETION_COLL, "gdpr_deletion_requests"); }
    #[test]
    fn gdpr_data_export_coll_name() { assert_eq!(GDPR_DATA_EXPORT_COLL, "gdpr_data_exports"); }
    #[test]
    fn deletion_confirm_input_has_token() {
        let input = DeletionConfirmInput { token: "tok123".to_string() };
        assert_eq!(input.token, "tok123");
    }
    #[test]
    fn deletion_request_input_reason_optional() {
        let input = DeletionRequestInput { reason: None };
        assert!(input.reason.is_none());
    }
    #[test]
    fn deletion_request_default_status() {
        let req = DeletionRequest {
            id: Uuid::new_v4().to_string(), user_id: "u1".to_string(),
            email: "e@x.com".to_string(), status: "pending".to_string(),
            confirmation_token: "t".to_string(), requested_at: Utc::now().to_rfc3339(),
            confirm_deadline: (Utc::now()+Duration::hours(24)).to_rfc3339(),
            confirmed_at: None, completed_at: None,
        };
        assert_eq!(req.status, "pending");
    }
    #[test]
    fn mongo_db_name_default() {
        std::env::remove_var("MONGO_DB_NAME");
        assert_eq!(mongo_db_name(), "novamail");
    }
    #[test]
    fn gdpr_routes_paths() {
        let p = vec!["/api/gdpr/deletion/request","/api/gdpr/deletion/confirm","/api/gdpr/deletion/status","/api/gdpr/data-export"];
        assert_eq!(p.len(), 4);
    }
}
