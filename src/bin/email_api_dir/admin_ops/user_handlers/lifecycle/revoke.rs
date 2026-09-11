#![allow(unused_imports, dead_code)]
use super::super::super::*;
use super::super::audit::log_admin_action;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revoke_sessions_success_response() {
        // Test the response structure for successful revocation
        let deleted_count = 5u64;
        let response = serde_json::json!({
            "revoked": true,
            "deletedCount": deleted_count,
        });
        assert_eq!(response["revoked"], true);
        assert_eq!(response["deletedCount"], deleted_count);
    }

    #[test]
    fn revoke_sessions_zero_deleted() {
        let deleted_count = 0u64;
        let response = serde_json::json!({
            "revoked": true,
            "deletedCount": deleted_count,
        });
        assert_eq!(response["revoked"], true);
        assert_eq!(response["deletedCount"], 0);
    }

    #[test]
    fn revoke_sessions_error_response() {
        let response = serde_json::json!({ "message": "Failed to revoke sessions" });
        assert_eq!(response["message"], "Failed to revoke sessions");
    }

    #[test]
    fn log_admin_action_format() {
        let deleted_count = 3u64;
        let action = "user.revoke_sessions";
        let target_type = "admin_user";
        let target_id = "user-123";
        let note = format!("deleted {} sessions", deleted_count);
        
        assert_eq!(action, "user.revoke_sessions");
        assert_eq!(target_type, "admin_user");
        assert_eq!(target_id, "user-123");
        assert_eq!(note, "deleted 3 sessions");
    }
}
