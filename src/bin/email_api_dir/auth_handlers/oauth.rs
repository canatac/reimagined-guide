use actix_web::{web, HttpRequest, HttpResponse, Responder};
use serde_json::json;
use uuid::Uuid;

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
    _req: HttpRequest,
    _query: web::Query<OAuthCallbackQuery>,
) -> impl Responder {
    HttpResponse::Ok().json(json!({ "status": "ok" }))
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
            code: Some("valid_code".to_string()),
            state: Some("state-123".to_string()),
        };
        assert_eq!(query.code.unwrap(), "valid_code");
        assert_eq!(query.state.unwrap(), "state-123");
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
}
