// oauth.rs — Handlers OAuth (start + callback). Extraits de auth_handlers.rs.
#![allow(unused_imports, dead_code)]
use super::super::*;
use super::login::make_session;

#[derive(Deserialize)]
pub(crate) struct OAuthCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
}

/// Resolve the OAuth provider from the request path.
///
/// The web client may request either the canonical route
/// `/api/auth/oauth/{provider}` or a relative start path such as
/// `/api/auth/oauth/github` built from a base URL that is empty. Both
/// resolve to the same provider here.
fn provider_from_path(path: &str) -> Option<String> {
    let trimmed = path.trim_start_matches('/').trim_end_matches('/');
    let provider = trimmed.rsplit('/').next().unwrap_or(trimmed);
    normalize_oauth_provider(provider)
}

/// Build the absolute GitHub authorization URL for a provider.
/// Returns None when the provider is not supported.
fn github_authorize_url(provider: &str, state: &str) -> Option<String> {
    if provider != "github" {
        return None;
    }
    let client_id = env::var("GITHUB_CLIENT_ID").ok().filter(|v| !v.is_empty())?;
    let callback_base = env::var("OAUTH_CALLBACK_BASE_URL")
        .unwrap_or_else(|_| "https://mail.misfits.ai".to_string());
    let redirect_uri = format!("{}/api/auth/oauth/github/callback", callback_base.trim_end_matches('/'));
    Some(format!(
        "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&state={}&scope=user:email",
        client_id,
        urlencoding::encode(&redirect_uri),
        state
    ))
}

pub(crate) async fn auth_oauth_start(req: actix_web::HttpRequest) -> impl Responder {
    let provider = match provider_from_path(req.path()) {
        Some(p) => p,
        None => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({ "message": "Unsupported OAuth provider." }))
        }
    };
    let state = Uuid::new_v4().to_string();

    // The client may have built a relative URL (for example
    // '/api/auth/oauth/github') and cannot follow a bare redirect target.
    // Return the absolute authorization URL in the body so the client can
    // navigate to it directly; the Location header is kept for clients that
    // still follow redirects.
    let auth_url = match github_authorize_url(&provider, &state) {
        Some(url) => url,
        None => {
            if provider != "github" {
                return HttpResponse::BadRequest()
                    .json(serde_json::json!({ "message": "Unsupported OAuth provider." }));
            }
            eprintln!("OAuth start: GITHUB_CLIENT_ID is not set");
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "OAuth provider not configured." }));
        }
    };

    HttpResponse::Ok()
        .insert_header(("Location", auth_url.clone()))
        .json(serde_json::json!({ "authorizationUrl": auth_url, "state": state, "provider": provider }))
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
    fn provider_from_canonical_path() {
        assert_eq!(provider_from_path("/api/auth/oauth/github").as_deref(), Some("github"));
    }

    #[test]
    fn provider_from_relative_path() {
        // The web client builds this relative path when its base URL is empty.
        assert_eq!(provider_from_path("api/auth/oauth/github").as_deref(), Some("github"));
    }

    #[test]
    fn provider_from_start_path() {
        assert_eq!(provider_from_path("/api/auth/oauth/github/start").as_deref(), Some("github"));
    }

    #[test]
    fn provider_from_unsupported() {
        assert!(provider_from_path("/api/auth/oauth/gitlab").is_none());
    }

    #[test]
    fn authorize_url_is_absolute() {
        std::env::set_var("GITHUB_CLIENT_ID", "test_client_id");
        std::env::set_var("OAUTH_CALLBACK_BASE_URL", "https://mail.misfits.ai");
        let url = github_authorize_url("github", "state-1").unwrap();
        assert!(url.starts_with("https://github.com/login/oauth/authorize?"));
        assert!(url.contains("client_id=test_client_id"));
        assert!(url.contains("redirect_uri=https%3A%2F%2Fmail.misfits.ai%2Fapi%2Fauth%2Foauth%2Fgithub%2Fcallback"));
        assert!(url.contains("state=state-1"));
        assert!(url.contains("scope=user:email"));
    }

    #[test]
    fn authorize_url_requires_client_id() {
        std::env::remove_var("GITHUB_CLIENT_ID");
        assert!(github_authorize_url("github", "state-1").is_none());
    }

    #[test]
    fn authorize_url_rejects_other_provider() {
        assert!(github_authorize_url("google", "state-1").is_none());
    }

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
    fn oauth_github_email_format() {
        let gh_login = "testuser";
        let email = format!("{}@github.oauth.misfits.ai", gh_login);
        assert_eq!(email, "testuser@github.oauth.misfits.ai");
    }

    #[test]
    fn oauth_github_frontend_redirect_format() {
        let frontend_base = "https://mail.misfits.ai";
        let token = "test-token";
        let redirect = format!(
            "{}/oauth/callback?token={}&provider={}",
            frontend_base.trim_end_matches('/'),
            urlencoding::encode(token),
            "github"
        );
        assert!(redirect.contains("/oauth/callback"));
        assert!(redirect.contains("token=test-token"));
        assert!(redirect.contains("provider=github"));
    }

    #[test]
    fn oauth_session_creation() {
        let session = make_session("test@github.oauth.misfits.ai", "Test User");
        assert_eq!(session.session.user.email, "test@github.oauth.misfits.ai");
        assert_eq!(session.session.user.display_name, "Test User");
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
}
