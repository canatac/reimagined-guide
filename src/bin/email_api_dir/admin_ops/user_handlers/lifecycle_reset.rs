#![allow(unused_imports, dead_code)]
use super::super::*;
use super::audit::log_admin_action;

use super::lifecycle_shared::*;

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
        Some(if generated { "auto-generated".to_string() } else { "manual".to_string() }),
        None,
    )
    .await;

    HttpResponse::Ok().json(serde_json::json!({
        "reset": true,
        "user": user,
        "generated": generated,
        "password": clear_for_response,
    }))
}
