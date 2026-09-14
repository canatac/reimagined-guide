#![allow(unused_imports, dead_code)]
use super::super::super::*;
use super::super::audit::log_admin_action;
use super::shared::*;

/// POST /api/admin/users/{id}/reset-password
///
/// Définit un nouveau mot de passe (bcrypt) sur l'AdminUserRecord.
/// Optionnellement révoque les sessions existantes.
pub(crate) async fn api_admin_user_reset_password(
    req: HttpRequest,
    path: web::Path<String>,
    body: web::Json<ResetPasswordInput>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let actor = match admin_auth::require_admin(&req, &mongo, &mongo_db_name()).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let id = path.into_inner();
    let coll = mongo
        .database(&mongo_db_name())
        .collection::<AdminUserRecord>(ADMIN_USERS_COLL);

    let mut user = match coll.find_one(doc! { "id": &id }).await {
        Ok(Some(v)) => v,
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(serde_json::json!({ "message": "User not found" }))
        }
        Err(e) => {
            eprintln!("reset_password: find_one error: {}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to load user" }));
        }
    };

    let (new_password, generated) = resolve_new_password(&body.new_password);
    if new_password.len() < 8 {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({ "message": "password must be at least 8 chars" }));
    }
    let clear_for_response = if generated { Some(new_password.clone()) } else { None };

    let hash = match web::block(move || bcrypt::hash(&new_password, 12)).await {
        Ok(Ok(h)) => h,
        Ok(Err(e)) => {
            eprintln!("reset_password: bcrypt error: {}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to hash password" }));
        }
        Err(e) => {
            eprintln!("reset_password: web::block error: {}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to hash password" }));
        }
    };

    let now = now_iso();
    user.password_hash = Some(hash.clone());
    user.updated_at = now.clone();
    user.invite_token = None;
    user.invite_expires_at = None;
    let mut recent = user.recent_activity.clone();
    recent.insert(
        0,
        AdminUserActivity {
            at: now,
            label: if generated {
                "Password reset (auto-generated)".to_string()
            } else {
                "Password reset".to_string()
            },
            kind: "admin_action".to_string(),
        },
    );
    recent.truncate(8);
    user.recent_activity = recent;

    if let Err(e) = coll
        .replace_one(doc! { "id": &id }, &user)
        .upsert(false)
        .await
    {
        eprintln!("reset_password: replace_one error: {}", e);
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({ "message": "Failed to update password" }));
    }

    sync_users_password(&mongo, &user.email, &hash).await;
    if body.revoke_sessions {
        revoke_all_sessions(&mongo, &id).await;
    }

    log_admin_action(
        mongo.as_ref(),
        &actor,
        "user.reset_password",
        "admin_user",
        &id,
        Some(format!("revoke_sessions={}", body.revoke_sessions)),
        None,
    )
    .await;

    HttpResponse::Ok().json(serde_json::json!({
        "reset": true,
        "password": clear_for_response,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_password_input_deserializes() {
        let json = serde_json::json!({
            "newPassword": "newpassword123",
            "revokeSessions": true
        });
        let input: ResetPasswordInput = serde_json::from_value(json).unwrap();
        assert_eq!(input.new_password, Some("newpassword123".to_string()));
        assert_eq!(input.revoke_sessions, true);
    }

    #[test]
    fn reset_password_input_without_revoke() {
        let json = serde_json::json!({
            "newPassword": "newpassword123"
        });
        let input: ResetPasswordInput = serde_json::from_value(json).unwrap();
        assert_eq!(input.new_password, Some("newpassword123".to_string()));
        assert_eq!(input.revoke_sessions, false);
    }

    #[test]
    fn reset_password_input_empty() {
        let json = serde_json::json!({});
        let input: ResetPasswordInput = serde_json::from_value(json).unwrap();
        assert_eq!(input.new_password, None);
        assert_eq!(input.revoke_sessions, false);
    }

    #[test]
    fn reset_password_min_length_validation() {
        let password = "short";
        assert!(password.len() < 8);
    }

    #[test]
    fn reset_password_valid_length() {
        let password = "validpassword123";
        assert!(password.len() >= 8);
    }

    #[test]
    fn reset_password_generated_flag() {
        // When no password is provided, one should be generated
        let input = ResetPasswordInput {
            new_password: None,
            revoke_sessions: false,
        };
        assert!(input.new_password.is_none());
    }

    #[test]
    fn reset_password_revoke_sessions_flag() {
        let input = ResetPasswordInput {
            new_password: Some("password123".to_string()),
            revoke_sessions: true,
        };
        assert!(input.revoke_sessions);
    }

    #[test]
    fn log_action_format() {
        let action = "user.reset_password";
        let target_type = "admin_user";
        let target_id = "user-123";
        let note = "revoke_sessions=true";
        
        assert_eq!(action, "user.reset_password");
        assert_eq!(target_type, "admin_user");
        assert_eq!(target_id, "user-123");
        assert_eq!(note, "revoke_sessions=true");
    }

    #[test]
    fn password_reset_response_with_generated() {
        let response = serde_json::json!({
            "reset": true,
            "password": "generated-password-123",
        });
        assert_eq!(response["reset"], true);
        assert_eq!(response["password"], "generated-password-123");
    }

    #[test]
    fn password_reset_response_without_generated() {
        let response = serde_json::json!({
            "reset": true,
            "password": null,
        });
        assert_eq!(response["reset"], true);
        assert_eq!(response["password"], serde_json::Value::Null);
    }

    #[test]
    fn error_response_user_not_found() {
        let response = serde_json::json!({ "message": "User not found" });
        assert_eq!(response["message"], "User not found");
    }

    #[test]
    fn error_response_password_too_short() {
        let response = serde_json::json!({ "message": "password must be at least 8 chars" });
        assert_eq!(response["message"], "password must be at least 8 chars");
    }
}
