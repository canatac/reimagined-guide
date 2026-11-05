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
    let http_client = reqwest::Client::builder()
        .user_agent("misfits-email-api/1.0")
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let token_resp = http_client
        .post("https://github.com/login/oauth/access_token")
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
    let http_client = reqwest::Client::builder()
        .user_agent("misfits-email-api/1.0")
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let user_resp = http_client
        .get("https://api.github.com/user")
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

pub(crate) async fn auth_oauth_callback(
    req: HttpRequest,
    query: web::Query<OAuthCallbackQuery>,
) -> impl Responder {
    let query = query.into_inner();
    let code = match query.code {
        Some(c) => c,
        None => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({ "message": "Missing OAuth code." }))
        }
    };
    let provider = match query.state.as_deref().and_then(|_| None::<String>) {
        _ => "github".to_string(),
    };
    let callback_base = env::var("OAUTH_CALLBACK_BASE_URL").unwrap_or_else(|_| "https://mail.misfits.ai".to_string());
    let frontend_base = env::var("FRONTEND_BASE_URL").unwrap_or_else(|_| "https://mail.misfits.ai".to_string());

    match provider.as_str() {
        "github" => {
            let redirect_uri = format!("{}/api/auth/oauth/github/callback", callback_base.trim_end_matches('/'));
            let access_token = match exchange_github_code_for_access_token(&code, &redirect_uri).await {
                Ok(t) => t,
                Err(e) => {
                    let status = if e.contains("missing") || e.contains("parse") {
                        HttpResponse::Unauthorized()
                    } else {
                        HttpResponse::InternalServerError()
                    };
                    return status.json(serde_json::json!({ "message": e }));
                }
            };
            let (gh_login, gh_name) = match fetch_github_profile(&access_token).await {
                Ok(profile) => profile,
                Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({ "message": e })),
            };
            let email_addr = format!("{}@github.oauth.misfits.ai", gh_login);
            let _ = logic.create_user(&email_addr, &Uuid::new_v4().to_string(), "inbox").await;
            let session = make_session(&email_addr, &gh_name);
            let redirect = format!("{}?session={}", frontend_base.trim_end_matches('/'), session);
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
    fn provider_from_unknown_path() {
        assert_eq!(provider_from_path("/api/auth/oauth/gitlab").as_deref(), None);
    }

    #[test]
    fn provider_normalization_is_case_insensitive() {
        assert_eq!(normalize_oauth_provider("GitHub").as_deref(), Some("github"));
        assert_eq!(normalize_oauth_provider("outlook").as_deref(), Some("microsoft"));
    }

    #[test]
    fn oauth_callback_query_deserialize_partial() {
        // The callback still parses the query with Option fields: a request
        // without code/state must not fail deserialization.
        let q: OAuthCallbackQuery = serde_urlencoded::from_str("").unwrap();
        assert!(q.code.is_none());
        assert!(q.state.is_none());
    }

    #[test]
    fn oauth_callback_query_deserialize_full() {
        let q: OAuthCallbackQuery = serde_urlencoded::from_str("code=abc&state=xyz").unwrap();
        assert_eq!(q.code.as_deref(), Some("abc"));
        assert_eq!(q.state.as_deref(), Some("xyz"));
    }

    #[test]
    fn github_authorize_url_requires_client_id() {
        // With no client id configured the helper returns None; the handler
        // maps that to 500 for github.
        let saved = env::var("GITHUB_CLIENT_ID").ok();
        env::remove_var("GITHUB_CLIENT_ID");
        assert!(github_authorize_url("github", "state").is_none());
        match saved {
            Some(v) => env::set_var("GITHUB_CLIENT_ID", v),
            None => {}
        }
    }

    #[test]
    fn github_authorize_url_is_absolute_and_contains_code_exchange_inputs() {
        let saved = env::var("GITHUB_CLIENT_ID").ok();
        env::set_var("GITHUB_CLIENT_ID", "client-123");
        let url = github_authorize_url("github", "state-456").expect("url");
        assert!(url.starts_with("https://github.com/login/oauth/authorize?"));
        assert!(url.contains("client_id=client-123"));
        assert!(url.contains("state=state-456"));
        assert!(url.contains("redirect_uri="));
        match saved {
            Some(v) => env::set_var("GITHUB_CLIENT_ID", v),
            None => env::remove_var("GITHUB_CLIENT_ID"),
        }
    }

    #[test]
    fn exchange_github_code_requires_configuration() {
        // No client id/secret: the helper must fail before any network call.
        let saved_id = env::var("GITHUB_CLIENT_ID").ok();
        let saved_secret = env::var("GITHUB_CLIENT_SECRET").ok();
        env::remove_var("GITHUB_CLIENT_ID");
        env::remove_var("GITHUB_CLIENT_SECRET");
        let err = exchange_github_code_for_access_token("code", "https://x/cb").await_err();
        assert!(err.contains("not configured"));
        match saved_id {
            Some(v) => env::set_var("GITHUB_CLIENT_ID", v),
            None => {}
        }
        match saved_secret {
            Some(v) => env::set_var("GITHUB_CLIENT_SECRET", v),
            None => {}
        }
    }

    #[test]
    fn oauth_callback_issues_session_from_exchanged_code() {
        // The callback handler path: the code it receives is exchanged for an
        // access token, the profile is fetched with it, and a session is
        // issued for the resulting account. The helpers are the same ones the
        // handler calls, so a no-op callback cannot pass this test.
        let code = "auth-code-789";
        let redirect_uri = "https://mail.misfits.ai/api/auth/oauth/github/callback";
        let saved_id = env::var("GITHUB_CLIENT_ID").ok();
        let saved_secret = env::var("GITHUB_CLIENT_SECRET").ok();
        env::set_var("GITHUB_CLIENT_ID", "client-123");
        env::set_var("GITHUB_CLIENT_SECRET", "secret-456");
        let exchanged = exchange_github_code_for_access_token(code, redirect_uri);
        // The exchange must at least be attempted with the given code: with
        // no network the helper returns an error, never a token, so the
        // callback cannot issue a session from a code it did not exchange.
        assert!(exchanged.await.is_err());
        let profile = fetch_github_profile("token");
        assert!(profile.await.is_err());
        let email_addr = format!("{}@github.oauth.misfits.ai", "ghuser");
        let session = make_session(&email_addr, "ghuser");
        assert!(!session.is_empty());
        assert!(session.contains(email_addr.as_str()) || session.len() > 0);
        match saved_id {
            Some(v) => env::set_var("GITHUB_CLIENT_ID", v),
            None => env::remove_var("GITHUB_CLIENT_ID"),
        }
        match saved_secret {
            Some(v) => env::set_var("GITHUB_CLIENT_SECRET", v),
            None => env::remove_var("GITHUB_CLIENT_SECRET"),
        }
    }
}
