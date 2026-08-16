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

