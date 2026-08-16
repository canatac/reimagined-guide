#![allow(unused_imports, dead_code)]
use super::super::*;
use super::audit::log_admin_action;

/// POST /api/admin/users/{id}/revoke-sessions
pub(crate) async fn api_admin_user_revoke_sessions(
    req: HttpRequest,
    path: web::Path<String>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let actor = match admin_auth::require_admin(&req, &mongo, &mongo_db_name()).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let id = path.into_inner();
    let sessions = mongo
        .database(&mongo_db_name())
        .collection::<admin_auth::AdminSession>(admin_auth::ADMIN_SESSIONS_COLL);
    match sessions.delete_many(doc! { "user_id": &id }).await {
        Ok(res) => {
            log_admin_action(
                mongo.as_ref(),
                &actor,
                "user.revoke_sessions",
                "admin_user",
                &id,
                Some(format!("deleted {} sessions", res.deleted_count)),
                None,
            )
            .await;
            HttpResponse::Ok().json(serde_json::json!({
                "revoked": true,
                "deletedCount": res.deleted_count,
            }))
        }
        Err(e) => {
            eprintln!("revoke_sessions: error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to revoke sessions" }))
        }
    }
}
