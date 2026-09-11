#![allow(unused_imports, dead_code)]
use super::super::*;
use super::audit::log_admin_action;

/// Validates that a role is one of the allowed values.
pub(crate) fn is_valid_role(role: &str) -> bool {
    let r = role.trim().to_ascii_lowercase();
    ["user", "admin", "support"].contains(&r.as_str())
}

/// Validates that a status is one of the allowed values.
pub(crate) fn is_valid_status(status: &str) -> bool {
    let s = status.trim().to_ascii_lowercase();
    ["active", "restricted"].contains(&s.as_str())
}

/// Returns the default status when none is provided.
pub(crate) fn default_status() -> String {
    "active".to_string()
}

/// Generates a unique user ID.
pub(crate) fn generate_user_id() -> String {
    format!("u_{}", Uuid::new_v4().simple())
}

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
    if !is_valid_role(&role) {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({ "message": "role must be user|admin|support" }));
    }

    let status = body
        .status
        .as_deref()
        .unwrap_or("active")
        .trim()
        .to_ascii_lowercase();
    if !is_valid_status(&status) {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({ "message": "status must be active|restricted" }));
    }

    let id = body
        .id
        .clone()
        .unwrap_or_else(|| generate_user_id());
    let now = now_iso();

    let user = AdminUserRecord {
        id: id.clone(),
        email: body.email.trim().to_string(),
        display_name: body.display_name.clone(),
        role,
        status,
        two_factor_enabled: body.two_factor_enabled.unwrap_or(false),
        last_login_at: None,
        last_activity_at: Some(now.clone()),
        sessions24h: 0,
        actions7d: 0,
        change_requests30d: 0,
        recent_activity: vec![AdminUserActivity {
            at: now.clone(),
            label: "User created".to_string(),
            kind: "admin_action".to_string(),
        }],
        created_at: now.clone(),
        updated_at: now,
        password_hash: None,
        invite_token: None,
        invite_expires_at: None,
        invited_at: None,
        notes: None,
    };

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_valid_role_accepts_user() {
        assert!(is_valid_role("user"));
        assert!(is_valid_role("User"));
        assert!(is_valid_role("  user  "));
    }

    #[test]
    fn is_valid_role_accepts_admin() {
        assert!(is_valid_role("admin"));
        assert!(is_valid_role("ADMIN"));
    }

    #[test]
    fn is_valid_role_accepts_support() {
        assert!(is_valid_role("support"));
    }

    #[test]
    fn is_valid_role_rejects_invalid() {
        assert!(!is_valid_role("superadmin"));
        assert!(!is_valid_role(""));
        assert!(!is_valid_role("root"));
    }

    #[test]
    fn is_valid_status_accepts_active() {
        assert!(is_valid_status("active"));
        assert!(is_valid_status("Active"));
        assert!(is_valid_status("  active  "));
    }

    #[test]
    fn is_valid_status_accepts_restricted() {
        assert!(is_valid_status("restricted"));
    }

    #[test]
    fn is_valid_status_rejects_invalid() {
        assert!(!is_valid_status("inactive"));
        assert!(!is_valid_status(""));
        assert!(!is_valid_status("pending"));
    }

    #[test]
    fn default_status_is_active() {
        assert_eq!(default_status(), "active");
    }

    #[test]
    fn generate_user_id_has_prefix() {
        let id = generate_user_id();
        assert!(id.starts_with("u_"));
        assert!(id.len() > 2);
    }

    #[test]
    fn generate_user_id_is_unique() {
        let id1 = generate_user_id();
        let id2 = generate_user_id();
        assert_ne!(id1, id2);
    }
}
