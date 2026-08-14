// auth_handlers.rs — extracted from email_api_dir/main.rs Sprint 2
// Handlers: auth_login, auth_register, auth_logout, auth_refresh,
//           auth_oauth_start, auth_oauth_callback,
//           api_2fa_verify, api_password_reset_request, api_password_reset_confirm,
//           api_patch_user_locale

use super::*;

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
pub(crate) struct OAuthCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
}

fn default_2fa_method() -> String { "email".to_string() }

#[derive(Deserialize)]
pub(crate) struct TwoFactorVerifyRequest {
    pub email: String,
    pub code: String,
    #[serde(default = "default_2fa_method")]
    pub method: String,
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

pub(crate) fn make_session(email: &str, display_name: &str) -> AuthResponse {
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
            access_token: Uuid::new_v4().to_string(),
            refresh_token: Uuid::new_v4().to_string(),
            expires_at: now + 3_600_000,
            refresh_expires_at: now + 604_800_000,
            issued_at: now,
        },
    }
}

// ─── TOTP helpers ─────────────────────────────────────────────────────────

fn compute_hotp(key: &[u8], counter: u64) -> u32 {
    type HmacSha1 = Hmac<Sha1>;
    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(&counter.to_be_bytes());
    let result = mac.finalize().into_bytes();
    let offset = (result[19] & 0x0f) as usize;
    let code = ((result[offset] as u32 & 0x7f) << 24)
        | ((result[offset + 1] as u32) << 16)
        | ((result[offset + 2] as u32) << 8)
        | (result[offset + 3] as u32);
    code % 1_000_000
}

pub(crate) fn verify_totp(secret_b32: &str, code: &str) -> bool {
    use constant_time_eq::constant_time_eq;
    let s = secret_b32.to_uppercase();
    let pad = s.len() % 8;
    let padded = if pad == 0 { s } else { format!("{}{}", s, "=".repeat(8 - pad)) };
    let key = match BASE32.decode(padded.as_bytes()) { Ok(k) => k, Err(_) => return false };
    let t = Utc::now().timestamp() / 30;
    for delta in [-1i64, 0, 1] {
        let counter = (t + delta).max(0) as u64;
        let candidate = format!("{:06}", compute_hotp(&key, counter));
        if constant_time_eq(candidate.as_bytes(), code.as_bytes()) { return true; }
    }
    false
}

pub(crate) fn generate_totp_secret() -> String {
    BASE32.encode(Uuid::new_v4().as_bytes())
}

pub(crate) fn generate_otp_code() -> String {
    let b = Uuid::new_v4();
    let n = u32::from_be_bytes([b.as_bytes()[0], b.as_bytes()[1], b.as_bytes()[2], b.as_bytes()[3]]);
    format!("{:06}", n % 1_000_000)
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
            HttpResponse::Ok().json(make_session(&req.email, &display))
        }
        Ok(None) => {
            let env_user = env::var("SMTP_USERNAME").unwrap_or_default();
            let env_pass = env::var("SMTP_PASSWORD").unwrap_or_default();
            if req.email == env_user || req.email == format!("{}@misfits.ai", env_user) {
                if req.password == env_pass {
                    return HttpResponse::Ok().json(make_session(&req.email, &env_user));
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
                    return HttpResponse::Ok().json(make_session(&req.email, &env_user));
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

pub(crate) async fn auth_oauth_start(path: web::Path<String>) -> impl Responder {
    let provider_raw = path.into_inner();
    let provider = match normalize_oauth_provider(&provider_raw) {
        Some(p) => p,
        None => return HttpResponse::BadRequest().json(serde_json::json!({ "message": "Unsupported OAuth provider." })),
    };
    let state = Uuid::new_v4().to_string();
    let callback_base = env::var("OAUTH_CALLBACK_BASE_URL").unwrap_or_else(|_| "https://mail.misfits.ai".to_string());
    let auth_url = match provider.as_str() {
        "github" => {
            let client_id = match env::var("GITHUB_CLIENT_ID").ok().filter(|v| !v.is_empty()) {
                Some(id) => id,
                None => { eprintln!("OAuth start: GITHUB_CLIENT_ID is not set"); return HttpResponse::InternalServerError().json(serde_json::json!({ "message": "OAuth provider not configured." })); }
            };
            let redirect_uri = format!("{}/api/auth/oauth/github/callback", callback_base.trim_end_matches('/'));
            format!("https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&state={}&scope=user:email", client_id, urlencoding::encode(&redirect_uri), state)
        }
        _ => return HttpResponse::BadRequest().json(serde_json::json!({ "message": "Unsupported OAuth provider." })),
    };
    HttpResponse::Found().insert_header(("Location", auth_url)).finish()
}

pub(crate) async fn auth_oauth_callback(
    path: web::Path<String>,
    query: web::Query<OAuthCallbackQuery>,
    logic: web::Data<Arc<Logic>>,
) -> impl Responder {
    let provider_raw = path.into_inner();
    let provider = match normalize_oauth_provider(&provider_raw) {
        Some(p) => p,
        None => return HttpResponse::BadRequest().json(serde_json::json!({ "message": "Unsupported OAuth provider." })),
    };
    let code = match query.code.as_ref().map(|v| v.trim()).filter(|v| !v.is_empty()) {
        Some(v) => v.to_string(),
        None => return HttpResponse::BadRequest().json(serde_json::json!({ "message": "Missing OAuth authorization code." })),
    };
    let callback_base = env::var("OAUTH_CALLBACK_BASE_URL").unwrap_or_else(|_| "https://mail.misfits.ai".to_string());
    let frontend_base = env::var("FRONTEND_BASE_URL").unwrap_or_else(|_| "https://mail.misfits.ai".to_string());
    let http_client = reqwest::Client::builder().user_agent("misfits-email-api/1.0").build().unwrap_or_else(|_| reqwest::Client::new());

    match provider.as_str() {
        "github" => {
            let client_id = env::var("GITHUB_CLIENT_ID").unwrap_or_default();
            let client_secret = env::var("GITHUB_CLIENT_SECRET").unwrap_or_default();
            if client_id.is_empty() || client_secret.is_empty() {
                return HttpResponse::InternalServerError().json(serde_json::json!({ "message": "OAuth provider not configured." }));
            }
            let redirect_uri = format!("{}/api/auth/oauth/github/callback", callback_base.trim_end_matches('/'));
            let token_resp = match http_client.post("https://github.com/login/oauth/access_token")
                .header("Accept", "application/json")
                .json(&serde_json::json!({ "client_id": client_id, "client_secret": client_secret, "code": code, "redirect_uri": redirect_uri }))
                .send().await {
                Ok(r) => r, Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({ "message": format!("OAuth token exchange failed: {}", e) })),
            };
            let token_json: serde_json::Value = match token_resp.json().await {
                Ok(j) => j, Err(_) => return HttpResponse::InternalServerError().json(serde_json::json!({ "message": "OAuth token parse failed" })),
            };
            let access_token = match token_json.get("access_token").and_then(|v| v.as_str()) {
                Some(t) => t.to_string(), None => return HttpResponse::Unauthorized().json(serde_json::json!({ "message": "OAuth access token missing" })),
            };
            let user_resp = match http_client.get("https://api.github.com/user")
                .header("Authorization", format!("token {}", access_token))
                .header("Accept", "application/vnd.github.v3+json")
                .send().await {
                Ok(r) => r, Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({ "message": format!("GitHub user fetch failed: {}", e) })),
            };
            let user_json: serde_json::Value = match user_resp.json().await { Ok(j) => j, Err(_) => return HttpResponse::InternalServerError().json(serde_json::json!({ "message": "GitHub user parse failed" })) };
            let gh_login = user_json.get("login").and_then(|v| v.as_str()).unwrap_or("ghuser").to_string();
            let gh_name  = user_json.get("name").and_then(|v| v.as_str()).unwrap_or(&gh_login).to_string();
            let email_addr = format!("{}@github.oauth.misfits.ai", gh_login);
            let _ = logic.create_user(&email_addr, &Uuid::new_v4().to_string(), "inbox").await;
            let session = make_session(&email_addr, &gh_name);
            let token_param = urlencoding::encode(&session.session.access_token);
            let redirect = format!("{}/oauth/callback?token={}&provider=github", frontend_base.trim_end_matches('/'), token_param);
            HttpResponse::Found().insert_header(("Location", redirect)).finish()
        }
        _ => HttpResponse::BadRequest().json(serde_json::json!({ "message": "Unsupported OAuth provider." })),
    }
}

pub(crate) async fn api_2fa_verify(
    body: web::Json<TwoFactorVerifyRequest>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let db = mongo_db_name();
    if body.method == "totp" {
        let coll = mongo.database(&db).collection::<bson::Document>("users");
        let local = body.email.split('@').next().unwrap_or(&body.email);
        let user_doc = match coll.find_one(doc! { "$or": [{ "username": local }, { "username": &body.email }] }).await {
            Ok(Some(d)) => d,
            Ok(None) => return HttpResponse::Unauthorized().json(serde_json::json!({ "verified": false, "error": "User not found" })),
            Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({ "error": e.to_string() })),
        };
        let totp_secret = match user_doc.get_str("totp_secret").ok().filter(|s| !s.is_empty()) {
            Some(s) => s.to_string(),
            None => return HttpResponse::BadRequest().json(serde_json::json!({ "verified": false, "error": "TOTP not configured for this user" })),
        };
        if !verify_totp(&totp_secret, &body.code) {
            return HttpResponse::Unauthorized().json(serde_json::json!({ "verified": false, "error": "Invalid TOTP code" }));
        }
    } else {
        let coll = mongo.database(&db).collection::<bson::Document>("two_factor_codes");
        let now_ms = Utc::now().timestamp_millis();
        match coll.find_one(doc! { "email": &body.email, "code": &body.code, "used": false, "expires_at": { "$gt": bson::DateTime::from_millis(now_ms) } }).await {
            Ok(Some(d)) => { if let Ok(oid) = d.get_object_id("_id") { let _ = coll.update_one(doc! { "_id": oid }, doc! { "$set": { "used": true } }).await; } }
            Ok(None) => return HttpResponse::Unauthorized().json(serde_json::json!({ "verified": false, "error": "Invalid or expired code" })),
            Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({ "error": e.to_string() })),
        }
    }
    let display = body.email.split('@').next().unwrap_or(&body.email).to_string();
    let session = make_session(&body.email, &display);
    HttpResponse::Ok().json(serde_json::json!({ "verified": true, "session": session.session }))
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
