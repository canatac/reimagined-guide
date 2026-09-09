// session.rs — Auth request types + logout/refresh stubs. Handlers split : login.rs, register.rs, password_reset.rs.
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

// ─── Session record for MongoDB ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct UserSession {
    pub user_id: String,
    pub email: String,
    pub display_name: String,
    pub role: String,
    pub access_token: String,
    pub refresh_token: String,
    pub access_expires_at: i64,
    pub refresh_expires_at: i64,
    pub created_at: String,
}

// ─── Stateless stubs ────────────────────────────────────────────────────────

pub(crate) async fn auth_logout() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({}))
}

/// Refresh handler — validates the refresh token against MongoDB and issues a new session.
/// Previously this was a stub that returned a random session without validation.
pub(crate) async fn auth_refresh(
    req_http: actix_web::HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    // Extract refresh token from Authorization header or cookie
    let refresh_token = extract_refresh_token(&req_http);
    let token = match refresh_token {
        Some(t) => t,
        None => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "code": "AUTH_REQUIRED",
                "message": "Missing refresh token"
            }));
        }
    };

    // Validate the refresh token against the database
    let db_name = std::env::var("MONGODB_DATABASE")
        .unwrap_or_else(|_| "mailserver".to_string());
    
    match lookup_user_session_by_refresh(mongo.as_ref(), &db_name, &token).await {
        Some(session) => {
            // Check if refresh token is expired
            let now = chrono::Utc::now();
            if let Ok(exp) = chrono::DateTime::parse_from_rfc3339(&session.refresh_expires_at.to_string()) {
                if now > exp {
                    return HttpResponse::Unauthorized().json(serde_json::json!({
                        "code": "AUTH_INVALID",
                        "message": "Refresh token expired"
                    }));
                }
            }

            // Issue new tokens
            let new_access_token = uuid::Uuid::new_v4().to_string();
            let new_refresh_token = uuid::Uuid::new_v4().to_string();
            let access_expires_at = now.timestamp_millis() + 3_600_000; // 1 hour
            let refresh_expires_at = now.timestamp_millis() + 604_800_000; // 7 days

            // Persist the new session to MongoDB
            if let Err(e) = update_user_session_tokens(
                mongo.as_ref(),
                &db_name,
                &session.refresh_token,
                &new_access_token,
                &new_refresh_token,
                access_expires_at,
                refresh_expires_at,
            ).await {
                eprintln!("auth_refresh: failed to update session: {}", e);
            }

            // Return the new session
            HttpResponse::Ok().json(serde_json::json!({
                "session": {
                    "id": uuid::Uuid::new_v4().to_string(),
                    "user": {
                        "id": session.user_id,
                        "email": session.email,
                        "display_name": session.display_name,
                        "role": session.role,
                        "two_factor_enabled": false,
                        "created_at": session.created_at,
                        "updated_at": now.to_rfc3339(),
                    },
                    "accessToken": new_access_token,
                    "refreshToken": new_refresh_token,
                    "expiresAt": access_expires_at as u64,
                    "refreshExpiresAt": refresh_expires_at as u64,
                    "issuedAt": now.timestamp_millis() as u64,
                }
            }))
        }
        None => {
            HttpResponse::Unauthorized().json(serde_json::json!({
                "code": "AUTH_INVALID",
                "message": "Session token unknown or expired"
            }))
        }
    }
}

/// Extract refresh token from Authorization header or cookie.
fn extract_refresh_token(req: &actix_web::HttpRequest) -> Option<String> {
    // Check Authorization header first
    if let Some(h) = req.headers().get("Authorization") {
        if let Ok(s) = h.to_str() {
            if let Some(tok) = s.strip_prefix("Bearer ") {
                let t = tok.trim();
                if !t.is_empty() {
                    return Some(t.to_string());
                }
            }
        }
    }
    // Fall back to cookie
    if let Some(c) = req.cookie("refresh_token") {
        let v = c.value().trim().to_string();
        if !v.is_empty() {
            return Some(v);
        }
    }
    None
}

/// Look up a user session by refresh token.
pub(crate) async fn lookup_user_session_by_refresh(
    mongo: &mongodb::Client,
    db_name: &str,
    refresh_token: &str,
) -> Option<UserSession> {
    let coll = mongo
        .database(db_name)
        .collection::<UserSession>("user_sessions");
    match coll.find_one(doc! { "refresh_token": refresh_token }).await {
        Ok(Some(sess)) => Some(sess),
        Ok(None) => None,
        Err(e) => {
            eprintln!("lookup_user_session_by_refresh: find_one failed: {}", e);
            None
        }
    }
}

/// Update session tokens in MongoDB after refresh.
pub(crate) async fn update_user_session_tokens(
    mongo: &mongodb::Client,
    db_name: &str,
    old_refresh_token: &str,
    new_access_token: &str,
    new_refresh_token: &str,
    access_expires_at: i64,
    refresh_expires_at: i64,
) -> Result<(), mongodb::error::Error> {
    let coll = mongo
        .database(db_name)
        .collection::<UserSession>("user_sessions");
    let now = chrono::Utc::now();
    coll.update_one(
        doc! { "refresh_token": old_refresh_token },
        doc! {
            "$set": {
                "access_token": new_access_token,
                "refresh_token": new_refresh_token,
                "access_expires_at": access_expires_at,
                "refresh_expires_at": refresh_expires_at,
                "updated_at": now.to_rfc3339(),
            }
        },
    ).await?;
    Ok(())
}

/// Store a new user session in MongoDB.
pub(crate) async fn store_user_session(
    mongo: &mongodb::Client,
    db_name: &str,
    user_id: &str,
    email: &str,
    display_name: &str,
    role: &str,
    access_token: &str,
    refresh_token: &str,
    access_expires_at: i64,
    refresh_expires_at: i64,
) -> Result<(), mongodb::error::Error> {
    let coll = mongo
        .database(db_name)
        .collection::<UserSession>("user_sessions");
    let now = chrono::Utc::now();
    let session = UserSession {
        user_id: user_id.to_string(),
        email: email.to_string(),
        display_name: display_name.to_string(),
        role: role.to_string(),
        access_token: access_token.to_string(),
        refresh_token: refresh_token.to_string(),
        access_expires_at,
        refresh_expires_at,
        created_at: now.to_rfc3339(),
    };
    coll.insert_one(session).await?;
    Ok(())
}
