// login.rs — auth_login + session token helpers.
#![allow(unused_imports, dead_code)]
use super::super::*;
use super::session::LoginRequest;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn make_session_with_token_fields() {
        let response = make_session_with_token("test@example.com", "Test User", "token-123");
        assert_eq!(response.session.user.email, "test@example.com");
        assert_eq!(response.session.user.display_name, "Test User");
        assert_eq!(response.session.user.role, "admin");
        assert_eq!(response.session.access_token, "token-123");
        assert!(!response.session.user.two_factor_enabled);
    }

    #[test]
    fn make_session_with_token_generates_unique_ids() {
        let r1 = make_session_with_token("a@b.com", "A", "t1");
        let r2 = make_session_with_token("a@b.com", "A", "t1");
        assert_ne!(r1.session.id, r2.session.id);
        assert_ne!(r1.session.user.id, r2.session.user.id);
        assert_ne!(r1.session.refresh_token, r2.session.refresh_token);
    }

    #[test]
    fn make_session_generates_unique_tokens() {
        let r1 = make_session("test@example.com", "Test");
        let r2 = make_session("test@example.com", "Test");
        assert_ne!(r1.session.access_token, r2.session.access_token);
    }

    #[test]
    fn make_session_with_token_timestamps() {
        let before = Utc::now().timestamp_millis() as u64;
        let response = make_session_with_token("test@example.com", "Test", "tok");
        assert!(response.session.issued_at >= before);
        assert!(response.session.expires_at > response.session.issued_at);
        assert!(response.session.refresh_expires_at > response.session.expires_at);
    }

    #[test]
    fn make_session_with_token_empty_email() {
        let response = make_session_with_token("", "Test", "tok");
        assert_eq!(response.session.user.email, "");
        assert_eq!(response.session.user.display_name, "Test");
    }
}

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
            // Set session_token cookie for frontend persistence
            let cookie = actix_web::cookie::Cookie::build("session_token", &response.session.access_token)
                .path("/")
                .http_only(true)
                .secure(true)
                .same_site(actix_web::cookie::SameSite::Lax)
                .max_age(actix_web::cookie::time::Duration::hours(24))
                .finish();
            HttpResponse::Ok()
                .cookie(cookie)
                .json(response)
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
                    let cookie = actix_web::cookie::Cookie::build("session_token", &response.session.access_token)
                        .path("/")
                        .http_only(true)
                        .secure(true)
                        .same_site(actix_web::cookie::SameSite::Lax)
                        .max_age(actix_web::cookie::time::Duration::hours(24))
                        .finish();
                    return HttpResponse::Ok()
                        .cookie(cookie)
                        .json(response);
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
                    let cookie = actix_web::cookie::Cookie::build("session_token", &response.session.access_token)
                        .path("/")
                        .http_only(true)
                        .secure(true)
                        .same_site(actix_web::cookie::SameSite::Lax)
                        .max_age(actix_web::cookie::time::Duration::hours(24))
                        .finish();
                    return HttpResponse::Ok()
                        .cookie(cookie)
                        .json(response);
                }
            }
            HttpResponse::Unauthorized().json(serde_json::json!({ "message": i18n::t(&locale, "error-login-invalid", &[]) }))
        }
    }
}
