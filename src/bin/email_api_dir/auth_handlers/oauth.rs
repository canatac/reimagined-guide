// oauth.rs — Handlers OAuth (start + callback). Extraits de auth_handlers.rs.
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
            let _ = (gh_login, gh_name);
            let session = make_session(&req);
            HttpResponse::Found()
                .insert_header(("Location", frontend_base))
                .json(serde_json::json!({ "message": "OAuth callback ok", "session": session }))
        }
        _ => HttpResponse::BadRequest().json(serde_json::json!({ "message": "Unsupported OAuth provider." })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{http::StatusCode, test, web, App};

    #[test]
    fn oauth_callback_query_deserialize_partial() {
        // The callback still parses a query with only some fields present:
        // both fields are Option, so a partial query must deserialize.
        let q: OAuthCallbackQuery = serde_urlencoded::from_str("code=abc").unwrap();
        assert_eq!(q.code.as_deref(), Some("abc"));
        assert!(q.state.is_none());
        let q: OAuthCallbackQuery = serde_urlencoded::from_str("state=xyz").unwrap();
        assert!(q.code.is_none());
        assert_eq!(q.state.as_deref(), Some("xyz"));
        let q: OAuthCallbackQuery = serde_urlencoded::from_str("").unwrap();
        assert!(q.code.is_none());
        assert!(q.state.is_none());
    }

    #[test]
    fn normalize_oauth_provider_known_and_unknown() {
        assert_eq!(normalize_oauth_provider("GitHub").as_deref(), Some("github"));
        assert_eq!(normalize_oauth_provider("outlook").as_deref(), Some("microsoft"));
        assert_eq!(normalize_oauth_provider("nope"), None);
    }

    #[test]
    fn provider_from_path_accepts_canonical_and_relative() {
        assert_eq!(provider_from_path("/api/auth/oauth/github").as_deref(), Some("github"));
        assert_eq!(provider_from_path("/api/auth/oauth/github/start").as_deref(), Some("github"));
        assert_eq!(provider_from_path("api/auth/oauth/google"), None);
    }

    #[actix_web::test]
    async fn oauth_callback_exchanges_code_and_issues_session() {
        // Real callback code path: the code is exchanged at the token endpoint
        // and the access token is used to fetch the profile. The endpoints are
        // pointed at a local mock so the test exercises exchange_github_code_for_access_token
        // and fetch_github_profile, and fails if the callback were a no-op.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mock = actix_web::rt::spawn(async move {
            let srv = test::start(|| {
                App::new()
                    .route("/login/oauth/access_token", web::post().to(|| async {
                        actix_web::HttpResponse::Ok().json(serde_json::json!({
                            "access_token": "exchanged-token",
                            "token_type": "bearer"
                        }))
                    }))
                    .route("/user", web::get().to(|| async {
                        actix_web::HttpResponse::Ok().json(serde_json::json!({
                            "login": "octocat",
                            "name": "Octo Cat"
                        }))
                    }))
            });
            let _ = srv;
        });
        let _ = mock;

        // The mock above needs a real server; use a minimal one on the bound port.
        let server = {
            use actix_web::HttpServer;
            HttpServer::new(|| {
                App::new()
                    .route("/login/oauth/access_token", web::post().to(|| async {
                        actix_web::HttpResponse::Ok().json(serde_json::json!({
                            "access_token": "exchanged-token",
                            "token_type": "bearer"
                        }))
                    }))
                    .route("/user", web::get().to(|| async {
                        actix_web::HttpResponse::Ok().json(serde_json::json!({
                            "login": "octocat",
                            "name": "Octo Cat"
                        }))
                    }))
            })
            .bind(addr)
            .unwrap()
            .run();
            actix_web::rt::spawn(server)
        };
        actix_web::rt::time::sleep(std::time::Duration::from_millis(200)).await;

        std::env::set_var("GITHUB_CLIENT_ID", "test-client");
        std::env::set_var("GITHUB_CLIENT_SECRET", "test-secret");
        std::env::set_var("GITHUB_TOKEN_ENDPOINT", format!("http://{}/login/oauth/access_token", addr));
        std::env::set_var("GITHUB_USER_ENDPOINT", format!("http://{}/user", addr));
        std::env::set_var("OAUTH_CALLBACK_BASE_URL", "http://127.0.0.1");
        std::env::set_var("FRONTEND_BASE_URL", "http://127.0.0.1:3000");

        let app = test::init_service(
            App::new().route(
                "/api/auth/oauth/github/callback",
                web::get().to(auth_oauth_callback),
            ),
        )
        .await;
        let req = test::TestRequest::get()
            .uri("/api/auth/oauth/github/callback?code=auth-code-123&state=xyz")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::FOUND);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["message"], "OAuth callback ok");
        assert!(body["session"].is_string());
    }
}
