// session.rs — Core session handlers : login/register/logout/refresh + password reset + patch locale.
// Extraits de auth_handlers.rs. OAuth → oauth.rs, TOTP/2FA → totp.rs.
#![allow(unused_imports, dead_code)]
use super::super::*;

// ─── Auth types ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub(crate) struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub(crate) struct RegisterRequest {
    #[serde(default)]
    pub first_name: String,
    #[serde(default)]
    pub last_name: String,
    /// Alias optionnel → alias@misfits.ai → prenom.nom@misfits.ai
    #[serde(default)]
    pub alias: Option<String>,
    pub password: String,
    #[serde(default)]
    pub condition_accepted: bool,
}

#[derive(Deserialize)]
pub(crate) struct PasswordResetRequestBody {
    pub email: String,
}

#[derive(Deserialize)]
pub(crate) struct PasswordResetConfirmBody {
    pub token: String,
    pub new_password: String,
}

#[derive(Deserialize)]
pub(crate) struct PatchLocaleRequest {
    pub locale: String,
}

// ─── Session builder (shared) ───────────────────────────────────────────────

/// Cherche l'utilisateur dans `admin_users` par email; s'il est actif,
/// persiste une session admin et renvoie le token à utiliser côté client.
async fn issue_session_if_admin(
    mongo: &mongodb::Client,
    email: &str,
) -> Option<String> {
    let db_name = std::env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let coll = mongo
        .database(&db_name)
        .collection::<AdminUserRecord>(super::super::admin_ops::ADMIN_USERS_COLL);
    let email_lc = email.trim().to_lowercase();
    let user_opt = match coll.find_one(doc! { "email": &email_lc }).await {
        Ok(Some(u)) => Some(u),
        Ok(None) => match coll.find_one(doc! { "email": email }).await {
            Ok(Some(u)) => Some(u),
            Ok(None) => None,
            Err(e) => {
                eprintln!("issue_session_if_admin: find_one (raw) failed: {}", e);
                None
            }
        },
        Err(e) => {
            eprintln!("issue_session_if_admin: find_one failed: {}", e);
            return None;
        }
    };
    let user = match user_opt {
        Some(u) => u,
        None => return None,
    };
    if user.status != "active" {
        return None;
    }
    let session = super::super::admin_auth::issue_admin_session(
        mongo,
        &db_name,
        &user.id,
        &user.email,
        &user.role,
        None,
        None,
    )
    .await;
    Some(session.token)
}

pub(crate) fn make_session(email: &str, display_name: &str) -> AuthResponse {
    make_session_with_token(email, display_name, &Uuid::new_v4().to_string())
}

pub(crate) fn make_session_with_token(
    email: &str,
    display_name: &str,
    access_token: &str,
) -> AuthResponse {
    let now = Utc::now().timestamp_millis() as u64;
    AuthResponse {
        session: SessionResponse {
            id: Uuid::new_v4().to_string(),
            user: UserResponse {
                id: Uuid::new_v4().to_string(),
                email: email.to_string(),
                display_name: display_name.to_string(),
                role: "admin".to_string(),
                two_factor_enabled: false,
                created_at: Utc::now().to_rfc3339(),
                updated_at: Utc::now().to_rfc3339(),
            },
            access_token: access_token.to_string(),
            refresh_token: Uuid::new_v4().to_string(),
            expires_at: now + 3_600_000,
            refresh_expires_at: now + 604_800_000,
            issued_at: now,
        },
    }
}

// ─── Handlers ─────────────────────────────────────────────────────────────

pub(crate) async fn auth_login(
    req: web::Json<LoginRequest>,
    req_http: actix_web::HttpRequest,
    logic: web::Data<Arc<Logic>>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let locale = i18n::resolve_locale(&get_accept_language(&req_http), None);
    match logic.authenticate_user(&req.email, &req.password).await {
        Ok(Some(user)) => {
            let display = if user.mailbox.is_empty() { req.email.clone() } else { user.mailbox.clone() };
            let response = match issue_session_if_admin(mongo.as_ref(), &req.email).await {
                Some(token) => make_session_with_token(&req.email, &display, &token),
                None => make_session(&req.email, &display),
            };
            HttpResponse::Ok().json(response)
        }
        Ok(None) => {
            let env_user = env::var("SMTP_USERNAME").unwrap_or_default();
            let env_pass = env::var("SMTP_PASSWORD").unwrap_or_default();
            if req.email == env_user || req.email == format!("{}@misfits.ai", env_user) {
                if req.password == env_pass {
                    let response = match issue_session_if_admin(mongo.as_ref(), &req.email).await {
                        Some(token) => make_session_with_token(&req.email, &env_user, &token),
                        None => make_session(&req.email, &env_user),
                    };
                    return HttpResponse::Ok().json(response);
                }
            }
            let ip = req_ip_str(&req_http);
            let ev = simple_smtp_server::security::AuthEvent::new(
                simple_smtp_server::security::AuthEventKind::ApiLogin, &ip, false,
            );
            let mc = mongo.clone();
            tokio::spawn(async move { simple_smtp_server::security::log_auth_event(&mc, ev).await; });
            HttpResponse::Unauthorized().json(serde_json::json!({ "message": i18n::t(&locale, "error-login-invalid", &[]) }))
        }
        Err(e) => {
            eprintln!("Auth error: {}", e);
            let env_user = env::var("SMTP_USERNAME").unwrap_or_default();
            let env_pass = env::var("SMTP_PASSWORD").unwrap_or_default();
            if req.email == env_user || req.email == format!("{}@misfits.ai", env_user) {
                if req.password == env_pass {
                    let response = match issue_session_if_admin(mongo.as_ref(), &req.email).await {
                        Some(token) => make_session_with_token(&req.email, &env_user, &token),
                        None => make_session(&req.email, &env_user),
                    };
                    return HttpResponse::Ok().json(response);
                }
            }
            HttpResponse::Unauthorized().json(serde_json::json!({ "message": i18n::t(&locale, "error-login-invalid", &[]) }))
        }
    }
}

pub(crate) async fn auth_register(
    req: web::Json<RegisterRequest>,
    req_http: actix_web::HttpRequest,
    logic: web::Data<Arc<Logic>>,
    bus: web::Data<EventBus>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let locale = i18n::resolve_locale(&get_accept_language(&req_http), None);
    if !req.condition_accepted {
        return HttpResponse::BadRequest().json(serde_json::json!({ "code": "CONDITIONS_NOT_ACCEPTED", "message": i18n::t(&locale, "error-conditions-required", &[]) }));
    }
    if req.password.len() < 8 {
        return HttpResponse::BadRequest().json(serde_json::json!({ "code": "INVALID_PASSWORD", "message": i18n::t(&locale, "error-password-too-short", &[]) }));
    }
    let local_part = match build_misfits_local(&req.first_name, &req.last_name) {
        Some(l) => l,
        None => return HttpResponse::BadRequest().json(serde_json::json!({ "code": "MISSING_IDENTITY", "message": i18n::t(&locale, "error-name-required", &[]) })),
    };
    let primary_email = format!("{}@misfits.ai", local_part);
    let alias_email: Option<String> = req.alias.as_deref().map(str::trim).filter(|s| !s.is_empty())
        .map(|a| normalize_segment(a)).filter(|n| !n.is_empty() && *n != local_part)
        .map(|n| format!("{}@misfits.ai", n));
    let display_name = {
        let first = req.first_name.trim();
        let last = req.last_name.trim();
        if first.is_empty() && last.is_empty() { local_part.clone() } else { format!("{} {}", first, last).trim().to_string() }
    };
    let password = req.password.clone();
    let password_hash = match web::block(move || bcrypt::hash(&password, 12)).await {
        Ok(Ok(h)) => h,
        Ok(Err(e)) => { eprintln!("bcrypt error: {}", e); return HttpResponse::InternalServerError().json(serde_json::json!({ "code": "INTERNAL_ERROR", "message": i18n::t(&locale, "error-account-creation-failed", &[]) })); }
        Err(e) => { eprintln!("bcrypt task error: {}", e); return HttpResponse::InternalServerError().json(serde_json::json!({ "code": "INTERNAL_ERROR", "message": i18n::t(&locale, "error-account-creation-failed", &[]) })); }
    };
    match logic.create_user(&primary_email, &password_hash, "inbox").await {
        Ok(_) => {}
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("E11000") || msg.contains("duplicate key") {
                return HttpResponse::Conflict().json(serde_json::json!({ "code": "EMAIL_TAKEN", "message": i18n::t(&locale, "error-email-taken", &[("email", &primary_email)]) }));
            }
            eprintln!("Register error ({}): {}", primary_email, e);
            return HttpResponse::InternalServerError().json(serde_json::json!({ "code": "INTERNAL_ERROR", "message": i18n::t(&locale, "error-account-creation-failed", &[]) }));
        }
    }
    if let Some(ref alias) = alias_email {
        if let Err(e) = logic.create_alias(alias, &primary_email).await {
            eprintln!("Alias creation error ({} → {}): {}", alias, primary_email, e);
        }
    }
    let welcome_subject = i18n::t(&locale, "email-welcome-subject", &[]);
    let welcome_body = welcome_email_html(&locale, &display_name, &primary_email, alias_email.as_deref());
    let welcome = Email {
        id: Uuid::new_v4().to_string(),
        from: "noreply@misfits.ai".to_string(),
        to: primary_email.clone(),
        subject: welcome_subject,
        body: welcome_body,
        headers: vec![("Content-Type".to_string(), "text/html; charset=utf-8".to_string())],
        flags: vec![],
        sequence_number: 1,
        uid: 1,
        internal_date: mongodb::bson::DateTime::from_millis(Utc::now().timestamp_millis()),
        dkim_signature: None,
    };
    if let Err(e) = logic.deliver_to_inbox(&local_part, &welcome).await {
        eprintln!("Welcome email delivery error ({}): {}", primary_email, e);
    } else {
        emit_event(&bus, &mongo, MailEvent {
            id: Uuid::new_v4().to_string(), kind: MailEventKind::Received,
            user_id: local_part.clone(), email_id: welcome.id.clone(),
            subject: welcome.subject.clone(), from: welcome.from.clone(),
            to: welcome.to.clone(), timestamp: Utc::now().to_rfc3339(),
        }).await;
    }
    let session = make_session(&primary_email, &display_name);
    HttpResponse::Created()
        .insert_header(("Content-Language", locale.as_str()))
        .json(serde_json::json!({ "email": primary_email, "alias": alias_email, "session": session.session, "locale": locale }))
}

pub(crate) async fn auth_logout() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({}))
}

pub(crate) async fn auth_refresh() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "session": {
            "id": Uuid::new_v4().to_string(),
            "user": { "id": Uuid::new_v4().to_string(), "email": "admin@misfits.ai", "displayName": "admin", "role": "admin", "twoFactorEnabled": false, "createdAt": Utc::now().to_rfc3339(), "updatedAt": Utc::now().to_rfc3339() },
            "accessToken": Uuid::new_v4().to_string(),
            "refreshToken": Uuid::new_v4().to_string(),
            "expiresAt": (Utc::now().timestamp_millis() + 3600000) as u64,
            "refreshExpiresAt": (Utc::now().timestamp_millis() + 604800000) as u64,
            "issuedAt": Utc::now().timestamp_millis() as u64,
        }
    }))
}

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
        internal_date: bson::DateTime::from_millis(Utc::now().timestamp_millis()), dkim_signature: None,
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
