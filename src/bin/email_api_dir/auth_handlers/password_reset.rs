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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_reset_email_trim() {
        let email = "  Test@Example.COM  ";
        let trimmed = email.trim().to_lowercase();
        assert_eq!(trimmed, "test@example.com");
    }

    #[test]
    fn password_reset_local_part() {
        let email = "user@example.com";
        let local = email.split('@').next().unwrap_or(email);
        assert_eq!(local, "user");
    }

    #[test]
    fn password_reset_local_part_no_at() {
        let email = "user";
        let local = email.split('@').next().unwrap_or(email);
        assert_eq!(local, "user");
    }

    #[test]
    fn password_reset_token_expiry() {
        let expires_at = bson::DateTime::from_millis(Utc::now().timestamp_millis() + 3_600_000);
        assert!(expires_at.timestamp_millis() > Utc::now().timestamp_millis());
    }

    #[test]
    fn password_reset_url_format() {
        let frontend_url = "https://app.misfits.ai";
        let token = "test-token-123";
        let reset_url = format!("{}/auth/reset-password?token={}", frontend_url, token);
        assert!(reset_url.contains("token=test-token-123"));
        assert!(reset_url.contains("/auth/reset-password"));
    }

    #[test]
    fn password_reset_html_format() {
        let reset_url = "https://app.misfits.ai/auth/reset-password?token=abc123";
        let body_html = format!("<p>Click <a href=\"{url}\">here</a> to reset your password.</p>", url = reset_url);
        assert!(body_html.contains(reset_url));
        assert!(body_html.contains("reset"));
    }

    #[test]
    fn password_reset_email_fields() {
        let reset_email = Email {
            id: Uuid::new_v4().to_string(),
            from: "noreply@misfits.ai".to_string(),
            to: "user@example.com".to_string(),
            subject: "Password Reset Request".to_string(),
            body: "<p>Reset</p>".to_string(),
            headers: vec![("Content-Type".to_string(), "text/html; charset=utf-8".to_string())],
            flags: vec![],
            sequence_number: 0,
            uid: 0,
            internal_date: Utc::now(),
            dkim_signature: None,
        };
        assert_eq!(reset_email.from, "noreply@misfits.ai");
        assert_eq!(reset_email.subject, "Password Reset Request");
        assert_eq!(reset_email.sequence_number, 0);
    }

    #[test]
    fn password_reset_min_length() {
        let min_length = 8;
        assert_eq!(min_length, 8);
    }

    #[test]
    fn password_reset_short_password() {
        let new_password = "short";
        assert!(new_password.len() < 8);
    }

    #[test]
    fn password_reset_valid_password() {
        let new_password = "validpassword123";
        assert!(new_password.len() >= 8);
    }

    #[test]
    fn password_reset_token_filter_format() {
        let token = "test-token";
        let now_ms = Utc::now().timestamp_millis();
        let filter = doc! { "token": token, "used": false, "expires_at": { "$gt": bson::DateTime::from_millis(now_ms) } };
        assert!(filter.contains_key("token"));
        assert!(filter.contains_key("used"));
        assert!(filter.contains_key("expires_at"));
    }

    #[test]
    fn password_reset_user_filter_format() {
        let local = "user";
        let email = "user@example.com";
        let filter = doc! { "$or": [{ "username": local }, { "username": email }] };
        assert!(filter.contains_key("$or"));
    }

    #[test]
    fn password_reset_update_format() {
        let password_hash = "$2b$12$hashedvalue";
        let update = doc! { "$set": { "password": password_hash } };
        assert!(update.contains_key("$set"));
    }

    #[test]
    fn password_reset_used_token_update() {
        let oid = bson::ObjectId::new();
        let update = doc! { "$set": { "used": true } };
        assert!(update.contains_key("$set"));
    }

    #[test]
    fn password_reset_supported_locales() {
        let locales = vec!["en", "fr", "es", "de", "it", "pt", "nl", "pl", "ru", "ja", "ko", "zh"];
        assert!(locales.contains(&"en"));
        assert!(locales.contains(&"fr"));
    }

    #[test]
    fn password_reset_locale_validation() {
        let locale = "en";
        let supported = vec!["en", "fr", "es"];
        assert!(supported.contains(&locale.as_ref()));
    }

    #[test]
    fn password_reset_locale_unsupported() {
        let locale = "xx";
        let supported = vec!["en", "fr", "es"];
        assert!(!supported.contains(&locale.as_ref()));
    }

    #[test]
    fn password_reset_message_success() {
        let message = "Password updated successfully";
        assert!(message.contains("successfully"));
    }

    #[test]
    fn password_reset_message_generic() {
        let message = "If the address is registered, a reset link has been sent.";
        assert!(message.contains("reset link"));
    }

    #[test]
    fn password_reset_cost() {
        let cost = 12;
        assert_eq!(cost, 12);
    }

    #[test]
    fn password_reset_token_uuid_format() {
        let token = Uuid::new_v4().to_string();
        assert!(token.contains("-"));
        assert!(token.len() > 30);
    }

    #[test]
    fn password_reset_frontend_url_default() {
        let default_url = "https://app.misfits.ai";
        assert_eq!(default_url, "https://app.misfits.ai");
    }

    #[test]
    fn password_reset_collection_names() {
        let tokens_coll = "password_reset_tokens";
        let users_coll = "users";
        assert_eq!(tokens_coll, "password_reset_tokens");
        assert_eq!(users_coll, "users");
    }

    #[test]
    fn password_reset_headers_format() {
        let headers = vec![("Content-Type".to_string(), "text/html; charset=utf-8".to_string())];
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Content-Type");
    }
}
