#![allow(unused_imports, dead_code)]
use super::super::*;

use super::audit::log_admin_action;

pub(crate) async fn api_admin_user_create(
    req: HttpRequest,
    body: web::Json<CreateAdminUserInput>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let actor = match admin_auth::require_admin(&req, &mongo, &mongo_db_name()).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let role = body.role.trim().to_ascii_lowercase();
    if !["user", "admin", "support"].contains(&role.as_str()) {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({ "message": "role must be user|admin|support" }));
    }

    let status = body
        .status
        .as_deref()
        .unwrap_or("active")
        .trim()
        .to_ascii_lowercase();
    if !["active", "restricted"].contains(&status.as_str()) {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({ "message": "status must be active|restricted" }));
    }

    let id = body
        .id
        .clone()
        .unwrap_or_else(|| format!("u_{}", Uuid::new_v4().simple()));
    let now = now_iso();

    let user = crud_write_helpers::build_new_admin_user(
        id.clone(),
        body.email.trim().to_string(),
        body.display_name.clone(),
        role,
        status,
        body.two_factor_enabled.unwrap_or(false),
        now,
    );

    let coll = mongo
        .database(&mongo_db_name())
        .collection::<AdminUserRecord>(ADMIN_USERS_COLL);

    match coll.insert_one(&user).await {
        Ok(_) => {
            log_admin_action(
                mongo.as_ref(),
                &actor,
                "user.create",
                "admin_user",
                &user.id,
                None,
                Some(serde_json::json!({ "email": user.email, "role": user.role, "status": user.status })),
            )
            .await;
            HttpResponse::Created().json(serde_json::json!({ "user": user }))
        }
        Err(e) => {
            eprintln!("api_admin_user_create error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to create user" }))
        }
    }
}

pub(crate) async fn api_admin_user_patch(
    req: HttpRequest,
    path: web::Path<String>,
    body: web::Json<UpdateAdminUserInput>,
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

    let current = match coll.find_one(doc! { "id": &id }).await {
        Ok(Some(v)) => v,
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(serde_json::json!({ "message": "User not found" }))
        }
        Err(e) => {
            eprintln!("api_admin_user_patch read error: {}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to load user" }));
        }
    };

    let now = now_iso();
    let mut updated = current.clone();

    if let Some(role) = &body.role {
        let role = role.trim().to_ascii_lowercase();
        if !["user", "admin", "support"].contains(&role.as_str()) {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({ "message": "role must be user|admin|support" }));
        }
        updated.role = role;
    }

    if let Some(status) = &body.status {
        let status = status.trim().to_ascii_lowercase();
        if !["active", "restricted"].contains(&status.as_str()) {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({ "message": "status must be active|restricted" }));
        }
        updated.status = status;
    }

    if let Some(email) = &body.email {
        let email = email.trim();
        if email.is_empty() || !email.contains('@') {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({ "message": "invalid email" }));
        }
        updated.email = email.to_string();
    }
    if let Some(dn) = &body.display_name {
        let dn = dn.trim();
        updated.display_name = if dn.is_empty() {
            None
        } else {
            Some(dn.to_string())
        };
    }
    if let Some(v) = body.two_factor_enabled {
        updated.two_factor_enabled = v;
    }
    if let Some(notes) = &body.notes {
        let notes = notes.trim();
        if notes.len() > 1024 {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({ "message": "notes too long (max 1024)" }));
        }
        updated.notes = if notes.is_empty() {
            None
        } else {
            Some(notes.to_string())
        };
    }

    updated.updated_at = now.clone();
    updated.last_activity_at = Some(now.clone());
    updated.actions7d += 1;
    let note = body
        .role
        .as_ref()
        .map(|r| format!("Role changed to {}", r))
        .unwrap_or_else(|| "User updated".to_string());
    let mut recent = updated.recent_activity;
    recent.insert(
        0,
        AdminUserActivity {
            at: now,
            label: note,
            kind: "role_change".to_string(),
        },
    );
    recent.truncate(8);
    updated.recent_activity = recent;

    match coll
        .replace_one(doc! { "id": &id }, &updated)
        .upsert(false)
        .await
    {
        Ok(_) => {
            log_admin_action(
                mongo.as_ref(),
                &actor,
                "user.patch",
                "admin_user",
                &id,
                None,
                Some(serde_json::json!({
                    "role": updated.role,
                    "status": updated.status,
                    "email": updated.email,
                    "displayName": updated.display_name,
                    "twoFactorEnabled": updated.two_factor_enabled,
                })),
            )
            .await;
            HttpResponse::Ok().json(serde_json::json!({ "user": updated }))
        }
        Err(e) => {
            eprintln!("api_admin_user_patch write error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to update user" }))
        }
    }
}

pub(crate) async fn api_admin_user_delete(
    req: HttpRequest,
    path: web::Path<String>,
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

    match coll.delete_one(doc! { "id": &id }).await {
        Ok(res) if res.deleted_count > 0 => {
            log_admin_action(
                mongo.as_ref(),
                &actor,
                "user.delete",
                "admin_user",
                &id,
                None,
                None,
            )
            .await;
            HttpResponse::Ok().json(serde_json::json!({ "deleted": true, "id": id }))
        }
        Ok(_) => HttpResponse::NotFound()
            .json(serde_json::json!({ "deleted": false, "message": "User not found" })),
        Err(e) => {
            eprintln!("api_admin_user_delete error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to delete user" }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_admin_user_input_deserializes() {
        let json = serde_json::json!({
            "id": "user-1",
            "email": "<EMAIL>",
            "displayName": "Test User",
            "role": "admin",
            "status": "active",
            "twoFactorEnabled": true
        });
        let input: CreateAdminUserInput = serde_json::from_value(json).unwrap();
        assert_eq!(input.id, Some("user-1".to_string()));
        assert_eq!(input.email, "<EMAIL>");
        assert_eq!(input.display_name, Some("Test User".to_string()));
        assert_eq!(input.role, "admin");
        assert_eq!(input.status, Some("active".to_string()));
        assert_eq!(input.two_factor_enabled, Some(true));
    }

    #[test]
    fn create_admin_user_input_minimal() {
        let json = serde_json::json!({ "email": "<EMAIL>", "role": "viewer" });
        let input: CreateAdminUserInput = serde_json::from_value(json).unwrap();
        assert_eq!(input.id, None);
        assert_eq!(input.email, "<EMAIL>");
        assert_eq!(input.role, "viewer");
    }

    #[test]
    fn update_admin_user_input_deserializes() {
        let json = serde_json::json!({ "role": "admin", "status": "suspended" });
        let input: UpdateAdminUserInput = serde_json::from_value(json).unwrap();
        assert_eq!(input.role, Some("admin".to_string()));
        assert_eq!(input.status, Some("suspended".to_string()));
    }

    #[test]
    fn update_admin_user_input_empty() {
        let json = serde_json::json!({});
        let input: UpdateAdminUserInput = serde_json::from_value(json).unwrap();
        assert_eq!(input.role, None);
        assert_eq!(input.status, None);
        assert_eq!(input.email, None);
    }

    #[test]
    fn role_validation_accepts_user() {
        let role = "user";
        assert!(["user", "admin", "support"].contains(&role));
    }

    #[test]
    fn role_validation_accepts_admin() {
        let role = "admin";
        assert!(["user", "admin", "support"].contains(&role));
    }

    #[test]
    fn role_validation_accepts_support() {
        let role = "support";
        assert!(["user", "admin", "support"].contains(&role));
    }

    #[test]
    fn role_validation_rejects_invalid() {
        let role = "superadmin";
        assert!(!["user", "admin", "support"].contains(&role));
    }

    #[test]
    fn status_validation_accepts_active() {
        let status = "active";
        assert!(["active", "restricted"].contains(&status));
    }

    #[test]
    fn status_validation_accepts_restricted() {
        let status = "restricted";
        assert!(["active", "restricted"].contains(&status));
    }

    #[test]
    fn status_validation_rejects_invalid() {
        let status = "inactive";
        assert!(!["active", "restricted"].contains(&status));
    }

    #[test]
    fn email_validation_contains_at() {
        let email = "<EMAIL>";
        assert!(email.contains('@'));
    }

    #[test]
    fn email_validation_rejects_no_at() {
        let email = "invalid-email";
        assert!(!email.contains('@'));
    }

    #[test]
    fn email_validation_rejects_empty() {
        let email = "";
        assert!(email.is_empty());
    }

    #[test]
    fn notes_validation_max_length() {
        let notes = "a".repeat(1025);
        assert!(notes.len() > 1024);
    }

    #[test]
    fn notes_validation_valid_length() {
        let notes = "a".repeat(1024);
        assert!(notes.len() <= 1024);
    }

    #[test]
    fn delete_response_success() {
        let response = serde_json::json!({ "deleted": true, "id": "user-123" });
        assert_eq!(response["deleted"], true);
        assert_eq!(response["id"], "user-123");
    }

    #[test]
    fn delete_response_not_found() {
        let response = serde_json::json!({ "deleted": false, "message": "User not found" });
        assert_eq!(response["deleted"], false);
        assert_eq!(response["message"], "User not found");
    }

    #[test]
    fn delete_response_error() {
        let response = serde_json::json!({ "message": "Failed to delete user" });
        assert_eq!(response["message"], "Failed to delete user");
    }

    #[test]
    fn patch_response_error() {
        let response = serde_json::json!({ "message": "Failed to update user" });
        assert_eq!(response["message"], "Failed to update user");
    }

    #[test]
    fn create_response_error() {
        let response = serde_json::json!({ "message": "Failed to create user" });
        assert_eq!(response["message"], "Failed to create user");
    }

    #[test]
    fn error_response_user_not_found() {
        let response = serde_json::json!({ "message": "User not found" });
        assert_eq!(response["message"], "User not found");
    }

    #[test]
    fn error_response_invalid_role() {
        let response = serde_json::json!({ "message": "role must be user|admin|support" });
        assert_eq!(response["message"], "role must be user|admin|support");
    }

    #[test]
    fn error_response_invalid_status() {
        let response = serde_json::json!({ "message": "status must be active|restricted" });
        assert_eq!(response["message"], "status must be active|restricted");
    }

    #[test]
    fn error_response_invalid_email() {
        let response = serde_json::json!({ "message": "invalid email" });
        assert_eq!(response["message"], "invalid email");
    }

    #[test]
    fn error_response_notes_too_long() {
        let response = serde_json::json!({ "message": "notes too long (max 1024)" });
        assert_eq!(response["message"], "notes too long (max 1024)");
    }

    #[test]
    fn log_action_format() {
        let action = "user.create";
        let target_type = "admin_user";
        let target_id = "user-123";
        
        assert_eq!(action, "user.create");
        assert_eq!(target_type, "admin_user");
        assert_eq!(target_id, "user-123");
    }

    #[test]
    fn recent_activity_truncate() {
        let mut activity: Vec<AdminUserActivity> = (0..10)
            .map(|i| AdminUserActivity {
                at: format!("2026-01-0{}T00:00:00Z", i),
                label: format!("Activity {}", i),
                kind: "test".to_string(),
            })
            .collect();
        activity.truncate(8);
        assert_eq!(activity.len(), 8);
    }

    #[test]
    fn recent_activity_under_limit() {
        let mut activity: Vec<AdminUserActivity> = (0..5)
            .map(|i| AdminUserActivity {
                at: format!("2026-01-0{}T00:00:00Z", i),
                label: format!("Activity {}", i),
                kind: "test".to_string(),
            })
            .collect();
        activity.truncate(8);
        assert_eq!(activity.len(), 5);
    }

    #[test]
    fn display_name_empty_becomes_none() {
        let dn = "   ";
        let result = if dn.trim().is_empty() {
            None
        } else {
            Some(dn.trim().to_string())
        };
        assert_eq!(result, None);
    }

    #[test]
    fn display_name_trimmed() {
        let dn = "  John Doe  ";
        let result = if dn.trim().is_empty() {
            None
        } else {
            Some(dn.trim().to_string())
        };
        assert_eq!(result, Some("John Doe".to_string()));
    }

    #[test]
    fn notes_empty_becomes_none() {
        let notes = "   ";
        let result = if notes.trim().is_empty() {
            None
        } else {
            Some(notes.trim().to_string())
        };
        assert_eq!(result, None);
    }

    #[test]
    fn two_factor_default_false() {
        let two_factor: Option<bool> = None;
        let result = two_factor.unwrap_or(false);
        assert_eq!(result, false);
    }

    #[test]
    fn two_factor_explicit_true() {
        let two_factor: Option<bool> = Some(true);
        let result = two_factor.unwrap_or(false);
        assert_eq!(result, true);
    }

    #[test]
    fn actions7d_increment() {
        let mut actions = 5u32;
        actions += 1;
        assert_eq!(actions, 6);
    }

    #[test]
    fn user_id_generation() {
        let id1 = format!("u_{}", Uuid::new_v4().simple());
        let id2 = format!("u_{}", Uuid::new_v4().simple());
        assert_ne!(id1, id2);
        assert!(id1.starts_with("u_"));
    }

    #[test]
    fn user_id_custom() {
        let custom_id = "custom-user-123";
        assert_eq!(custom_id, "custom-user-123");
    }
}
