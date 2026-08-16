// password_reset.rs — password reset request/confirm + locale patch.
#![allow(unused_imports, dead_code)]
use super::super::*;
use super::session::{PasswordResetRequestBody, PasswordResetConfirmBody, PatchLocaleRequest};

pub(crate) async fn api_password_reset_request(
    body: web::Json<PasswordResetRequestBody>,
    mongo: web::Data<Arc<mongodb::Client>>,
    logic: web::Data<Arc<Logic>>,
) -> impl Responder {
    let db = mongo_db_name();
    let email = body.email.trim().to_lowercase();
    let local = email.split('@').next().unwrap_or(&email).to_string();
    let users_coll = mongo.database(&db).collection::<bson::Document>("users");
    let user_exists = matches!(users_coll.find_one(doc! { "$or": [{ "username": &local }, { "username": &email }] }).await, Ok(Some(_)));
    if !user_exists {
        return HttpResponse::Ok().json(serde_json::json!({ "message": "If the address is registered, a reset link has been sent." }));
    }
    let token = Uuid::new_v4().to_string();
    let expires_at = bson::DateTime::from_millis(Utc::now().timestamp_millis() + 3_600_000);
    let tokens_coll = mongo.database(&db).collection::<bson::Document>("password_reset_tokens");
    let _ = tokens_coll.update_many(doc! { "email": &email, "used": false }, doc! { "$set": { "used": true } }).await;
    if let Err(e) = tokens_coll.insert_one(doc! { "token": &token, "email": &email, "expires_at": expires_at, "used": false }).await {
        eprintln!("password_reset_request insert error: {}", e);
        return HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Failed to create reset token" }));
    }
    let frontend_url = env::var("FRONTEND_URL").unwrap_or_else(|_| "https://app.misfits.ai".to_string());
    let reset_url = format!("{}/auth/reset-password?token={}", frontend_url, token);
    let body_html = format!("<p>Click <a href=\"{url}\">here</a> to reset your password. This link expires in 1 hour.</p><p>Or copy this link: {url}</p>", url = reset_url);
    let reset_email = Email {
        id: Uuid::new_v4().to_string(), from: "noreply@misfits.ai".to_string(), to: email.clone(),
        subject: "Password Reset Request".to_string(), body: body_html,
        headers: vec![("Content-Type".to_string(), "text/html; charset=utf-8".to_string())],
        flags: vec![], sequence_number: 0, uid: 0,
        internal_date: Utc::now(), dkim_signature: None,
    };
    if let Err(e) = logic.deliver_to_inbox(&local, &reset_email).await { eprintln!("password reset email delivery error: {}", e); }
    HttpResponse::Ok().json(serde_json::json!({ "message": "If the address is registered, a reset link has been sent." }))
}

pub(crate) async fn api_password_reset_confirm(
    body: web::Json<PasswordResetConfirmBody>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if body.new_password.len() < 8 {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Password must be at least 8 characters" }));
    }
    let db = mongo_db_name();
    let tokens_coll = mongo.database(&db).collection::<bson::Document>("password_reset_tokens");
    let now_ms = Utc::now().timestamp_millis();
    let token_doc = match tokens_coll.find_one(doc! { "token": &body.token, "used": false, "expires_at": { "$gt": bson::DateTime::from_millis(now_ms) } }).await {
        Ok(Some(d)) => d,
        Ok(None) => return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Invalid or expired token" })),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({ "error": e.to_string() })),
    };
    let email = match token_doc.get_str("email") { Ok(e) => e.to_string(), Err(_) => return HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Token data corrupted" })) };
    let local = email.split('@').next().unwrap_or(&email).to_string();
    let new_password = body.new_password.clone();
    let password_hash = match web::block(move || bcrypt::hash(&new_password, 12)).await {
        Ok(Ok(h)) => h,
        _ => return HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Password hashing failed" })),
    };
    let users_coll = mongo.database(&db).collection::<bson::Document>("users");
    match users_coll.update_one(doc! { "$or": [{ "username": &local }, { "username": &email }] }, doc! { "$set": { "password": &password_hash } }).await {
        Ok(r) if r.matched_count == 0 => return HttpResponse::NotFound().json(serde_json::json!({ "error": "User not found" })),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({ "error": e.to_string() })),
        _ => {}
    }
    if let Ok(oid) = token_doc.get_object_id("_id") { let _ = tokens_coll.update_one(doc! { "_id": oid }, doc! { "$set": { "used": true } }).await; }
    HttpResponse::Ok().json(serde_json::json!({ "message": "Password updated successfully" }))
}

pub(crate) async fn api_patch_user_locale(
    req: actix_web::HttpRequest,
    body: web::Json<PatchLocaleRequest>,
    logic: web::Data<Arc<Logic>>,
) -> impl Responder {
    if !i18n::SUPPORTED_LOCALES.contains(&body.locale.as_str()) {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "unsupported_locale", "supported": i18n::SUPPORTED_LOCALES }));
    }
    let username = resolve_user_id(&req);
    match logic.update_user_locale(&username, &body.locale).await {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({ "locale": body.locale })),
        Err(e) => { eprintln!("update_user_locale error: {}", e); HttpResponse::InternalServerError().json(serde_json::json!({ "error": "internal" })) }
    }
}
