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

/// Logout — closes the stored session of the access token (#751) and clears
/// the session cookies of the browser.
pub(crate) async fn auth_logout(
    req_http: actix_web::HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if let Some(token) = super::super::admin_auth::extract_token(&req_http) {
        super::session_store::close_session(mongo.get_ref().as_ref(), &token).await;
    }
    let mut ok = HttpResponse::Ok();
    for cookie in super::session_store::cleared_cookies() {
        ok.cookie(cookie);
    }
    ok.json(serde_json::json!({}))
}

/// Refresh handler — rotates the tokens of the stored session of the refresh
/// token (#751): the old refresh token is worth nothing afterwards. Unknown,
/// expired or already used: 401.
pub(crate) async fn auth_refresh(
    req_http: actix_web::HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let token = match extract_refresh_token(&req_http) {
        Some(t) => t,
        None => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "code": "AUTH_REQUIRED",
                "message": "Missing refresh token"
            }));
        }
    };
    match super::session_store::rotate_session(mongo.get_ref().as_ref(), &token).await {
        Some(stored) => {
            let response = super::session_store::response_of(&stored);
            let body = serde_json::to_value(&response).unwrap_or_default();
            super::session_store::with_session(HttpResponse::Ok(), &response, body)
        }
        None => HttpResponse::Unauthorized().json(serde_json::json!({
            "code": "AUTH_INVALID",
            "message": "Session token unknown or expired"
        })),
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

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::http::header::HeaderValue;

    #[test]
    fn extract_refresh_token_from_bearer() {
        let req = actix_web::test::TestRequest::default()
            .insert_header(("Authorization", "Bearer <PASSWORD>"))
            .to_http_request();
        assert_eq!(extract_refresh_token(&req), Some("my-token-123".to_string()));
    }

    #[test]
    fn extract_refresh_token_from_bearer_with_whitespace() {
        let req = actix_web::test::TestRequest::default()
            .insert_header(("Authorization", "Bearer   my-token  "))
            .to_http_request();
        assert_eq!(extract_refresh_token(&req), Some("my-token".to_string()));
    }

    #[test]
    fn extract_refresh_token_missing_header() {
        let req = actix_web::test::TestRequest::default()
            .to_http_request();
        assert_eq!(extract_refresh_token(&req), None);
    }

    #[test]
    fn extract_refresh_token_invalid_bearer_format() {
        let req = actix_web::test::TestRequest::default()
            .insert_header(("Authorization", "Basic dXNlcjpwYXNz"))
            .to_http_request();
        assert_eq!(extract_refresh_token(&req), None);
    }

    #[test]
    fn extract_refresh_token_empty_bearer() {
        let req = actix_web::test::TestRequest::default()
            .insert_header(("Authorization", "Bearer   "))
            .to_http_request();
        assert_eq!(extract_refresh_token(&req), None);
    }

    #[test]
    fn user_session_serialization() {
        let session = UserSession {
            user_id: "user-1".into(),
            email: "<EMAIL>".into(),
            display_name: "Test User".into(),
            role: "admin".into(),
            access_token: "access-123".into(),
            refresh_token: "refresh-456".into(),
            access_expires_at: 1234567890,
            refresh_expires_at: 9999999999,
            created_at: "2026-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_value(&session).unwrap();
        assert_eq!(json["user_id"], "user-1");
        assert_eq!(json["email"], "<EMAIL>");
        assert_eq!(json["role"], "admin");
        let parsed: UserSession = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.user_id, "user-1");
        assert_eq!(parsed.refresh_token, "refresh-456");
    }
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
