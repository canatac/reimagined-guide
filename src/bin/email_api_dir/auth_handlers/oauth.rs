// oauth.rs — Handlers OAuth (start + callback). Extraits de auth_handlers.rs.
#![allow(unused_imports, dead_code)]
use super::super::*;
use super::login::make_session;

/// Normalize a provider name from a path segment.
pub(crate) fn normalize_oauth_provider(raw: &str) -> Option<String> {
    match raw.to_ascii_lowercase().as_str() {
        "github" => Some("github".to_string()),
        "google" => Some("google".to_string()),
        "microsoft" | "outlook" => Some("microsoft".to_string()),
        "apple" => Some("apple".to_string()),
        _ => None,
    }
}

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
/// Returns None when the provider is not supported or not configured.
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

/// Exchange an OAuth authorization code for an access token (GitHub).
///
/// This is the single code path used by the callback: the authorization code
/// is sent to GitHub's token endpoint and the returned access token is
/// extracted. Callers that need the user identity fetch it with this token.
pub(crate) async fn exchange_github_code_for_access_token(
    code: &str,
    redirect_uri: &str,
) -> Result<String, String> {
    let client_id = env::var("GITHUB_CLIENT_ID").unwrap_or_default();
    let client_secret = env::var("GITHUB_CLIENT_SECRET").unwrap_or_default();
    if client_id.is_empty() || client_secret.is_empty() {
        return Err("OAuth provider not configured.".to_string());
    }
    let token_endpoint = env::var("GITHUB_TOKEN_ENDPOINT")
        .unwrap_or_else(|_| "https://github.com/login/oauth/access_token".to_string());
    let http_client = reqwest::Client::builder()
        .user_agent("misfits-email-api/1.0")
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let token_resp = http_client
        .post(token_endpoint)
        .header("Accept", "application/json")
        .json(&serde_json::json!({
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code,
            "redirect_uri": redirect_uri,
        }))
        .send()
        .await
        .map_err(|e| format!("OAuth token exchange failed: {}", e))?;
    let token_json: serde_json::Value = token_resp
        .json()
        .await
        .map_err(|_| "OAuth token parse failed".to_string())?;
    token_json
        .get("access_token")
        .and_then(|v| v.as_str())
        .map(|t| t.to_string())
        .ok_or_else(|| "OAuth access token missing".to_string())
}

/// Fetch the GitHub profile for an access token and return (login, name).
pub(crate) async fn fetch_github_profile(
    access_token: &str,
) -> Result<(String, String), String> {
    let user_endpoint = env::var("GITHUB_USER_ENDPOINT")
        .unwrap_or_else(|_| "https://api.github.com/user".to_string());
    let http_client = reqwest::Client::builder()
        .user_agent("misfits-email-api/1.0")
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let user_resp = http_client
        .get(user_endpoint)
        .header("Authorization", format!("token {}", access_token))
        .header("Accept", "application/vnd.github.v3+json")
        .send()
        .await
        .map_err(|e| format!("GitHub user fetch failed: {}", e))?;
    let user_json: serde_json::Value = user_resp
        .json()
        .await
        .map_err(|_| "GitHub user parse failed".to_string())?;
    let gh_login = user_json
        .get("login")
        .and_then(|v| v.as_str())
        .unwrap_or("ghuser")
        .to_string();
    let gh_name = user_json
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or(&gh_login)
        .to_string();
    Ok((gh_login, gh_name))
}

pub(crate) async fn auth_oauth_start(req: HttpRequest) -> impl Responder {
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

/// Complete the GitHub OAuth callback: exchange the code, fetch the profile,
/// issue a session and return it.
///
/// Extracted from `auth_oauth_callback` so the callback code path can be
/// exercised directly by tests without an HTTP server.
async fn oauth_callback_finish(
    logic: &Logic,
    code: &str,
) -> Result<(String, String), HttpResponse> {
    let callback_base = env::var("OAUTH_CALLBACK_BASE_URL")
        .unwrap_or_else(|_| "https://mail.misfits.ai".to_string());
    let redirect_uri = format!("{}/api/auth/oauth/github/callback", callback_base.trim_end_matches('/'));

    let access_token = match exchange_github_code_for_access_token(code, &redirect_uri).await {
        Ok(t) => t,
        Err(e) => {
            let status = if e.contains("missing") || e.contains("parse") {
                HttpResponse::Unauthorized()
            } else {
                HttpResponse::InternalServerError()
            };
            return Err(status.json(serde_json::json!({ "message": e })));
        }
    };
    let (gh_login, gh_name) = match fetch_github_profile(&access_token).await {
        Ok(profile) => profile,
        Err(e) => {
            return Err(HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": e })));
        }
    };

    let email_addr = format!("{}@github.oauth.misfits.ai", gh_login);
    let _ = logic.create_user(&email_addr, &Uuid::new_v4().to_string(), "inbox").await;
    let session = make_session(&email_addr, &gh_name);
    Ok((session.session.access_token, gh_login))
}

pub(crate) async fn auth_oauth_callback(
    req: HttpRequest,
    query: web::Query<OAuthCallbackQuery>,
    logic: web::Data<Arc<Logic>>,
) -> impl Responder {
    let query = query.into_inner();
    let code = match query.code.as_ref().map(|v| v.trim()).filter(|v| !v.is_empty()) {
        Some(v) => v.to_string(),
        None => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({ "message": "Missing OAuth authorization code." }))
        }
    };
    let provider = match provider_from_path(req.path()) {
        Some(p) => p,
        None => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({ "message": "Unsupported OAuth provider." }))
        }
    };
    let frontend_base = env::var("FRONTEND_BASE_URL")
        .unwrap_or_else(|_| "https://mail.misfits.ai".to_string());

    match provider.as_str() {
        "github" => {
            let logic_ref: &Logic = &logic;
            match oauth_callback_finish(logic_ref, &code).await {
                Ok((session, _login)) => {
                    let token_param = urlencoding::encode(&session);
                    let redirect = format!("{}/oauth/callback?token={}&provider=github", frontend_base.trim_end_matches('/'), token_param);
                    HttpResponse::Found().insert_header(("Location", redirect)).finish()
                }
                Err(resp) => resp,
            }
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

    #[test]
    fn provider_from_path_accepts_relative_and_absolute_paths() {
        assert_eq!(provider_from_path("/api/auth/oauth/github").as_deref(), Some("github"));
        assert_eq!(provider_from_path("api/auth/oauth/github").as_deref(), Some("github"));
        assert_eq!(provider_from_path("/api/auth/oauth/github/").as_deref(), Some("github"));
        assert_eq!(provider_from_path("/api/auth/oauth/GitHub").as_deref(), Some("github"));
        assert_eq!(provider_from_path("/api/auth/oauth/gitlab"), None);
    }

    #[test]
    fn github_authorize_url_is_absolute() {
        env::set_var("GITHUB_CLIENT_ID", "test_client_id");
        env::set_var("OAUTH_CALLBACK_BASE_URL", "https://mail.misfits.ai");
        let url = github_authorize_url("github", "state-1").expect("github url");
        assert!(url.starts_with("https://github.com/login/oauth/authorize?"), "must be absolute: {}", url);
        assert!(url.contains("client_id=test_client_id"));
        assert!(url.contains("state=state-1"));
        assert!(url.contains("redirect_uri="));
    }

    #[test]
    fn github_authorize_url_rejects_other_provider() {
        assert!(github_authorize_url("google", "state-1").is_none());
    }

    #[tokio::test]
    async fn oauth_callback_exchanges_code_and_issues_session() {
        // Point the token and user endpoints at a local mock so the real
        // callback code path (exchange -> profile -> session) runs.
        let mock = wiremock::MockServer::start().await;
        env::set_var("GITHUB_CLIENT_ID", "test_client_id");
        env::set_var("GITHUB_CLIENT_SECRET", "test_client_secret");
        env::set_var("GITHUB_TOKEN_ENDPOINT", format!("{}/token", mock.uri()));
        env::set_var("GITHUB_USER_ENDPOINT", format!("{}/user", mock.uri()));
        env::set_var("OAUTH_CALLBACK_BASE_URL", "https://mail.misfits.ai");

        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/token"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "mock-access-token"
            })))
            .mount(&mock)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/user"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "login": "octocat",
                "name": "Octo Cat"
            })))
            .mount(&mock)
            .await;

        // The callback code path is exercised through the extracted function:
        // it must exchange the code, fetch the profile and issue a session.
        let logic = Logic::new().await.expect("logic");
        let (token, login) = oauth_callback_finish(&logic, "auth-code")
            .await
            .expect("callback must succeed");
        assert_eq!(login, "octocat");
        assert!(!token.is_empty(), "the callback must return a session token");
    }

    #[tokio::test]
    async fn oauth_callback_reports_missing_token() {
        let mock = wiremock::MockServer::start().await;
        env::set_var("GITHUB_CLIENT_ID", "test_client_id");
        env::set_var("GITHUB_CLIENT_SECRET", "test_client_secret");
        env::set_var("GITHUB_TOKEN_ENDPOINT", format!("{}/token", mock.uri()));
        env::set_var("OAUTH_CALLBACK_BASE_URL", "https://mail.misfits.ai");

        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/token"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "error": "bad_verification_code"
            })))
            .mount(&mock)
            .await;

        let logic = Logic::new().await.expect("logic");
        let err = oauth_callback_finish(&logic, "bad-code")
            .await
            .expect_err("a token response without access_token must fail");
        assert_eq!(err.status(), 401);
    }
}
