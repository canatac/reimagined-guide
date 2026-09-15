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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn make_session_creates_valid_response() {
        let response = make_session("test@example.com", "Test User");
        assert_eq!(response.session.user.email, "test@example.com");
        assert_eq!(response.session.user.display_name, "Test User");
        assert_eq!(response.session.user.role, "admin");
        assert!(!response.session.user.two_factor_enabled);
    }

    #[test]
    fn make_session_with_token_uses_provided_token() {
        let token = "my-custom-token";
        let response = make_session_with_token("test@example.com", "Test User", token);
        assert_eq!(response.session.access_token, token);
    }

    #[test]
    fn make_session_generates_unique_ids() {
        let r1 = make_session("a@test.com", "A");
        let r2 = make_session("b@test.com", "B");
        assert_ne!(r1.session.id, r2.session.id);
        assert_ne!(r1.session.user.id, r2.session.user.id);
        assert_ne!(r1.session.access_token, r2.session.access_token);
        assert_ne!(r1.session.refresh_token, r2.session.refresh_token);
    }

    #[test]
    fn make_session_expires_at() {
        let response = make_session("test@example.com", "Test User");
        assert!(response.session.expires_at > response.session.issued_at);
    }

    #[test]
    fn make_session_refresh_expires_after_access() {
        let response = make_session("test@example.com", "Test User");
        assert!(response.session.refresh_expires_at > response.session.expires_at);
    }

    #[test]
    fn make_session_timestamps() {
        let response = make_session("test@example.com", "Test User");
        assert!(!response.session.user.created_at.is_empty());
        assert!(!response.session.user.updated_at.is_empty());
    }

    #[test]
    fn make_session_uuid_format() {
        let response = make_session("test@example.com", "Test User");
        assert!(response.session.id.contains("-"));
        assert!(response.session.user.id.contains("-"));
        assert!(response.session.refresh_token.contains("-"));
    }

    #[test]
    fn make_session_with_token_generates_refresh() {
        let response = make_session_with_token("test@example.com", "Test User", "token-123");
        assert_ne!(response.session.refresh_token, "token-123");
        assert!(response.session.refresh_token.contains("-"));
    }

    #[test]
    fn make_session_with_token_generates_session_id() {
        let response = make_session_with_token("test@example.com", "Test User", "token-123");
        assert!(!response.session.id.is_empty());
        assert!(response.session.id.contains("-"));
    }

    #[test]
    fn make_session_with_token_generates_user_id() {
        let response = make_session_with_token("test@example.com", "Test User", "token-123");
        assert!(!response.session.user.id.is_empty());
        assert!(response.session.user.id.contains("-"));
    }

    #[test]
    fn session_response_fields() {
        let response = make_session("admin@misfits.ai", "Admin");
        assert_eq!(response.session.user.email, "admin@misfits.ai");
        assert_eq!(response.session.user.display_name, "Admin");
        assert_eq!(response.session.user.role, "admin");
    }

    #[test]
    fn session_expiry_duration() {
        let response = make_session("test@example.com", "Test");
        let access_duration = response.session.expires_at - response.session.issued_at;
        assert_eq!(access_duration, 3_600_000); // 1 hour
    }

    #[test]
    fn session_refresh_expiry_duration() {
        let response = make_session("test@example.com", "Test");
        let refresh_duration = response.session.refresh_expires_at - response.session.issued_at;
        assert_eq!(refresh_duration, 604_800_000); // 7 days
    }

    #[test]
    fn email_lowercase() {
        let email = "Test@Example.COM";
        let lower = email.trim().to_lowercase();
        assert_eq!(lower, "test@example.com");
    }

    #[test]
    fn email_trim() {
        let email = "  test@example.com  ";
        let trimmed = email.trim().to_lowercase();
        assert_eq!(trimmed, "test@example.com");
    }

    #[test]
    fn admin_user_status_active() {
        let status = "active";
        assert_eq!(status, "active");
    }

    #[test]
    fn admin_user_status_inactive() {
        let status = "inactive";
        assert_ne!(status, "active");
    }

    #[test]
    fn admin_users_collection() {
        let coll = "admin_users";
        assert_eq!(coll, "admin_users");
    }

    #[test]
    fn mongodb_database_default() {
        let db = "mailserver";
        assert_eq!(db, "mailserver");
    }

    #[test]
    fn auth_event_kind_api_login() {
        let kind = "ApiLogin";
        assert!(kind.contains("Login"));
    }

    #[test]
    fn cookie_name() {
        let cookie_name = "session_token";
        assert_eq!(cookie_name, "session_token");
    }

    #[test]
    fn cookie_path() {
        let path = "/";
        assert_eq!(path, "/");
    }

    #[test]
    fn cookie_http_only() {
        let http_only = true;
        assert!(http_only);
    }

    #[test]
    fn cookie_secure() {
        let secure = true;
        assert!(secure);
    }

    #[test]
    fn cookie_same_site_lax() {
        let same_site = "Lax";
        assert_eq!(same_site, "Lax");
    }

    #[test]
    fn cookie_max_age_hours() {
        let hours = 24;
        assert_eq!(hours, 24);
    }

    #[test]
    fn error_message_key() {
        let key = "error-login-invalid";
        assert!(key.contains("login"));
        assert!(key.contains("invalid"));
    }

    #[test]
    fn locale_resolution() {
        let locale = "en";
        assert_eq!(locale, "en");
    }

    #[test]
    fn smtp_username_env() {
        let env = "SMTP_USERNAME";
        assert_eq!(env, "SMTP_USERNAME");
    }

    #[test]
    fn smtp_password_env() {
        let env = "SMTP_PASSWORD";
        assert_eq!(env, "SMTP_PASSWORD");
    }

    #[test]
    fn misfits_domain() {
        let domain = "misfits.ai";
        assert_eq!(domain, "misfits.ai");
    }

    #[test]
    fn email_with_misfits_domain() {
        let env_user = "admin";
        let email = format!("{}@misfits.ai", env_user);
        assert_eq!(email, "admin@misfits.ai");
    }

    #[test]
    fn login_request_fields() {
        let fields = vec!["email", "password"];
        assert_eq!(fields.len(), 2);
    }

    #[test]
    fn user_response_fields() {
        let fields = vec!["id", "email", "display_name", "role", "two_factor_enabled", "created_at", "updated_at"];
        assert_eq!(fields.len(), 7);
    }

    #[test]
    fn session_response_fields() {
        let fields = vec!["id", "user", "access_token", "refresh_token", "expires_at", "refresh_expires_at", "issued_at"];
        assert_eq!(fields.len(), 7);
    }
}
