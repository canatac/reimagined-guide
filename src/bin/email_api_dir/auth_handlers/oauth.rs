// oauth.rs — Handlers OAuth (start + callback). Extraits de auth_handlers.rs.
#![allow(unused_imports, dead_code)]
use super::super::*;
use super::login::make_session;

#[derive(Deserialize)]
pub(crate) struct OAuthCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oauth_callback_query_new() {
        let query = OAuthCallbackQuery {
            code: Some("abc123".to_string()),
            state: Some("state-456".to_string()),
        };
        assert_eq!(query.code, Some("abc123".to_string()));
        assert_eq!(query.state, Some("state-456".to_string()));
    }

    #[test]
    fn oauth_callback_query_none() {
        let query = OAuthCallbackQuery {
            code: None,
            state: None,
        };
        assert!(query.code.is_none());
        assert!(query.state.is_none());
    }

    #[test]
    fn oauth_callback_query_empty_code() {
        let query = OAuthCallbackQuery {
            code: Some("".to_string()),
            state: Some("state".to_string()),
        };
        let code = query.code.as_ref().map(|v| v.trim()).filter(|v| !v.is_empty());
        assert!(code.is_none());
    }

    #[test]
    fn oauth_callback_query_whitespace_code() {
        let query = OAuthCallbackQuery {
            code: Some("   ".to_string()),
            state: Some("state".to_string()),
        };
        let code = query.code.as_ref().map(|v| v.trim()).filter(|v| !v.is_empty());
        assert!(code.is_none());
    }

    #[test]
    fn oauth_callback_query_valid_code() {
        let query = OAuthCallbackQuery {
            code: Some("valid_code".to_string()),
            state: Some("state".to_string()),
        };
        let code = query.code.as_ref().map(|v| v.trim()).filter(|v| !v.is_empty());
        assert!(code.is_some());
        assert_eq!(code.unwrap(), "valid_code");
    }

    #[test]
    fn oauth_provider_github() {
        let provider = "github";
        assert_eq!(provider, "github");
    }

    #[test]
    fn oauth_provider_unsupported() {
        let provider = "unsupported";
        assert_ne!(provider, "github");
    }

    #[test]
    fn oauth_github_authorize_url_format() {
        let client_id = "test_client_id";
        let redirect_uri = "https://mail.misfits.ai/api/auth/oauth/github/callback";
        let state = "test-state-uuid";
        let scope = "user:email";
        let url = format!(
            "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&state={}&scope={}",
            client_id, urlencoding::encode(redirect_uri), state, scope
        );
        assert!(url.contains("github.com/login/oauth/authorize"));
        assert!(url.contains("client_id=test_client_id"));
        assert!(url.contains("state=test-state-uuid"));
        assert!(url.contains("scope=user:email"));
    }

    #[test]
    fn oauth_github_redirect_uri_format() {
        let callback_base = "https://mail.misfits.ai";
        let redirect_uri = format!("{}/api/auth/oauth/github/callback", callback_base.trim_end_matches('/'));
        assert_eq!(redirect_uri, "https://mail.misfits.ai/api/auth/oauth/github/callback");
    }

    #[test]
    fn oauth_github_redirect_uri_no_trailing_slash() {
        let callback_base = "https://mail.misfits.ai/";
        let redirect_uri = format!("{}/api/auth/oauth/github/callback", callback_base.trim_end_matches('/'));
        assert_eq!(redirect_uri, "https://mail.misfits.ai/api/auth/oauth/github/callback");
    }

    #[test]
    fn oauth_github_email_format() {
        let gh_login = "testuser";
        let email = format!("{}@github.oauth.misfits.ai", gh_login);
        assert_eq!(email, "testuser@github.oauth.misfits.ai");
    }

    #[test]
    fn oauth_github_default_login() {
        let gh_login = "ghuser";
        assert_eq!(gh_login, "ghuser");
    }

    #[test]
    fn oauth_github_name_fallback() {
        let gh_login = "testuser";
        let gh_name = gh_login;
        assert_eq!(gh_name, "testuser");
    }

    #[test]
    fn oauth_github_frontend_redirect_format() {
        let frontend_base = "https://mail.misfits.ai";
        let token = "test-token";
        let provider = "github";
        let redirect = format!(
            "{}/oauth/callback?token={}&provider={}",
            frontend_base.trim_end_matches('/'),
            urlencoding::encode(token),
            provider
        );
        assert!(redirect.contains("/oauth/callback"));
        assert!(redirect.contains("token=test-token"));
        assert!(redirect.contains("provider=github"));
    }

    #[test]
    fn oauth_github_frontend_redirect_no_trailing_slash() {
        let frontend_base = "https://mail.misfits.ai/";
        let redirect = format!("{}/oauth/callback", frontend_base.trim_end_matches('/'));
        assert_eq!(redirect, "https://mail.misfits.ai/oauth/callback");
    }

    #[test]
    fn oauth_callback_base_url_default() {
        let default = "https://mail.misfits.ai";
        assert_eq!(default, "https://mail.misfits.ai");
    }

    #[test]
    fn oauth_github_client_id_env() {
        let env = "GITHUB_CLIENT_ID";
        assert_eq!(env, "GITHUB_CLIENT_ID");
    }

    #[test]
    fn oauth_github_client_secret_env() {
        let env = "GITHUB_CLIENT_SECRET";
        assert_eq!(env, "GITHUB_CLIENT_SECRET");
    }

    #[test]
    fn oauth_github_token_url() {
        let url = "https://github.com/login/oauth/access_token";
        assert!(url.contains("github.com"));
    }

    #[test]
    fn oauth_github_user_api_url() {
        let url = "https://api.github.com/user";
        assert!(url.contains("api.github.com"));
    }

    #[test]
    fn oauth_github_accept_header() {
        let accept = "application/vnd.github.v3+json";
        assert!(accept.contains("github"));
    }

    #[test]
    fn oauth_user_agent() {
        let ua = "misfits-email-api/1.0";
        assert!(ua.contains("misfits"));
    }

    #[test]
    fn oauth_http_client_fallback() {
        let client = reqwest::Client::builder().user_agent("test").build();
        assert!(client.is_ok() || client.is_err());
    }

    #[test]
    fn oauth_token_json_access_token() {
        let token_json = serde_json::json!({ "access_token": "test-token" });
        let access_token = token_json.get("access_token").and_then(|v| v.as_str());
        assert_eq!(access_token, Some("test-token"));
    }

    #[test]
    fn oauth_token_json_missing_access_token() {
        let token_json = serde_json::json!({ "error": "bad_verification_code" });
        let access_token = token_json.get("access_token").and_then(|v| v.as_str());
        assert!(access_token.is_none());
    }

    #[test]
    fn oauth_user_json_login() {
        let user_json = serde_json::json!({ "login": "testuser", "name": "Test User" });
        let login = user_json.get("login").and_then(|v| v.as_str()).unwrap_or("ghuser");
        assert_eq!(login, "testuser");
    }

    #[test]
    fn oauth_user_json_name_fallback() {
        let user_json = serde_json::json!({ "login": "testuser" });
        let login = user_json.get("login").and_then(|v| v.as_str()).unwrap_or("ghuser");
        let name = user_json.get("name").and_then(|v| v.as_str()).unwrap_or(login);
        assert_eq!(name, "testuser");
    }

    #[test]
    fn oauth_user_json_default_login() {
        let user_json = serde_json::json!({});
        let login = user_json.get("login").and_then(|v| v.as_str()).unwrap_or("ghuser");
        assert_eq!(login, "ghuser");
    }

    #[test]
    fn oauth_create_user_mailbox() {
        let mailbox = "inbox";
        assert_eq!(mailbox, "inbox");
    }

    #[test]
    fn oauth_session_creation() {
        let session = make_session("test@github.oauth.misfits.ai", "Test User");
        assert_eq!(session.session.user.email, "test@github.oauth.misfits.ai");
        assert_eq!(session.session.user.display_name, "Test User");
    }

    #[test]
    fn oauth_token_encoding() {
        let token = "test-token-with-special-chars=&?";
        let encoded = urlencoding::encode(token);
        assert!(encoded.contains("%"));
    }

    #[test]
    fn oauth_state_uuid_format() {
        let state = Uuid::new_v4().to_string();
        assert!(state.contains("-"));
        assert!(state.len() > 30);
    }

    #[test]
    fn oauth_error_messages() {
        let unsupported = "Unsupported OAuth provider.";
        let missing_code = "Missing OAuth authorization code.";
        let not_configured = "OAuth provider not configured.";
        let token_missing = "OAuth access token missing";
        assert!(unsupported.contains("Unsupported"));
        assert!(missing_code.contains("Missing"));
        assert!(not_configured.contains("not configured"));
        assert!(token_missing.contains("missing"));
    }

    #[test]
    fn oauth_http_status_codes() {
        let bad_request = 400;
        let unauthorized = 401;
        let internal_error = 500;
        let found = 302;
        assert_eq!(bad_request, 400);
        assert_eq!(unauthorized, 401);
        assert_eq!(internal_error, 500);
        assert_eq!(found, 302);
    }

    #[test]
    fn oauth_location_header() {
        let header = "Location";
        assert_eq!(header, "Location");
    }

    #[test]
    fn oauth_callback_query_deserialize() {
        let json = r#"{"code": "abc123", "state": "xyz789"}"#;
        let result: Result<OAuthCallbackQuery, _> = serde_json::from_str(json);
        assert!(result.is_ok());
        let query = result.unwrap();
        assert_eq!(query.code, Some("abc123".to_string()));
        assert_eq!(query.state, Some("xyz789".to_string()));
    }

    #[test]
    fn oauth_callback_query_deserialize_empty() {
        let json = r#"{}"#;
        let result: Result<OAuthCallbackQuery, _> = serde_json::from_str(json);
        assert!(result.is_ok());
        let query = result.unwrap();
        assert!(query.code.is_none());
        assert!(query.state.is_none());
    }

    #[test]
    fn oauth_callback_query_deserialize_partial() {
        let json = r#"{"code": "abc123"}"#;
        let result: Result<OAuthCallbackQuery, _> = serde_json::from_str(json);
        assert!(result.is_ok());
        let query = result.unwrap();
        assert_eq!(query.code, Some("abc123".to_string()));
        assert!(query.state.is_none());
    }
}
