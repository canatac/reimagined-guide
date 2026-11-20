// oauth.rs — Connexion par GitHub (start + callback), #736.
//
// Le contrat est celui du site web (misfits-web) :
// - le navigateur est envoyé sur `/api/auth/oauth/github` : l'API répond par
//   une redirection 302 vers GitHub ;
// - au retour, l'API redirige vers `/api/auth/callback?session=<JSON en
//   base64>&provider=github` du site, ou `?error=<code>&provider=github`.
//
// Le paramètre `state` est gardé dans un cookie HttpOnly le temps de l'aller
// et retour, et comparé au retour : sans lui, aucune session n'est ouverte.
// Le compte est rattaché à l'identifiant numérique de GitHub, qui ne change
// pas, et non au login, qui peut être renommé puis repris.
#![allow(unused_imports, dead_code)]
use super::super::*;
use super::session_store::{open_session, session_cookies};
use base64::Engine;

#[derive(Deserialize)]
pub(crate) struct OAuthCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

/// Le cookie du `state`, limité aux routes OAuth et à 10 minutes.
pub(crate) const STATE_COOKIE: &str = "oauth_state";
pub(crate) const STATE_COOKIE_PATH: &str = "/api/auth/oauth";
pub(crate) const STATE_TTL_SECS: i64 = 600;
/// Le domaine des adresses des comptes GitHub.
pub(crate) const ACCOUNT_DOMAIN: &str = "github.oauth.misfits.ai";

fn callback_base() -> String {
    env::var("OAUTH_CALLBACK_BASE_URL").unwrap_or_else(|_| "https://mail.misfits.ai".to_string())
}

fn frontend_base() -> String {
    env::var("FRONTEND_BASE_URL").unwrap_or_else(|_| "https://mail.misfits.ai".to_string())
}

pub(crate) fn github_redirect_uri(callback_base: &str) -> String {
    format!("{}/api/auth/oauth/github/callback", callback_base.trim_end_matches('/'))
}

pub(crate) fn github_authorize_url(client_id: &str, callback_base: &str, state: &str) -> String {
    format!(
        "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&state={}&scope=user:email",
        urlencoding::encode(client_id),
        urlencoding::encode(&github_redirect_uri(callback_base)),
        urlencoding::encode(state)
    )
}

pub(crate) fn state_cookie(state: &str) -> actix_web::cookie::Cookie<'static> {
    actix_web::cookie::Cookie::build(STATE_COOKIE, state.to_string())
        .path(STATE_COOKIE_PATH)
        .http_only(true)
        .secure(true)
        .same_site(actix_web::cookie::SameSite::Lax)
        .max_age(actix_web::cookie::time::Duration::seconds(STATE_TTL_SECS))
        .finish()
}

pub(crate) fn cleared_state_cookie() -> actix_web::cookie::Cookie<'static> {
    let mut cookie = state_cookie("");
    cookie.set_max_age(actix_web::cookie::time::Duration::ZERO);
    cookie
}

/// Le `state` du retour est celui du cookie : tous deux présents, non vides
/// et égaux, comparés en temps constant.
pub(crate) fn state_matches(from_query: Option<&str>, from_cookie: Option<&str>) -> bool {
    match (from_query, from_cookie) {
        (Some(q), Some(c)) if !q.is_empty() && !c.is_empty() => {
            constant_time_eq::constant_time_eq(q.as_bytes(), c.as_bytes())
        }
        _ => false,
    }
}

/// L'utilisateur GitHub d'une réponse de `/user` : son identifiant numérique
/// et son login sont obligatoires.
#[derive(Debug, PartialEq)]
pub(crate) struct GithubUser {
    pub id: u64,
    pub login: String,
    pub name: String,
}

pub(crate) fn github_user_of(json: &serde_json::Value) -> Option<GithubUser> {
    let id = json.get("id").and_then(|v| v.as_u64()).filter(|id| *id > 0)?;
    let login = json.get("login").and_then(|v| v.as_str()).map(str::trim).filter(|l| !l.is_empty())?.to_string();
    let name = json
        .get("name")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .unwrap_or(&login)
        .to_string();
    Some(GithubUser { id, login, name })
}

/// L'adresse du compte d'un utilisateur GitHub, par son identifiant numérique.
pub(crate) fn account_email(user: &GithubUser) -> String {
    format!("gh{}@{}", user.id, ACCOUNT_DOMAIN)
}

/// L'URL du site qui reçoit la session.
pub(crate) fn web_session_url(frontend_base: &str, response: &AuthResponse) -> String {
    let json = serde_json::to_string(&response.session).unwrap_or_default();
    let encoded = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());
    format!(
        "{}/api/auth/callback?session={}&provider=github",
        frontend_base.trim_end_matches('/'),
        urlencoding::encode(&encoded)
    )
}

/// L'URL du site qui reçoit un échec : `access_denied` quand l'utilisateur a
/// refusé, sinon `oauth_failed`.
pub(crate) fn web_error_url(frontend_base: &str, error: &str) -> String {
    let code = if error == "access_denied" { "access_denied" } else { "oauth_failed" };
    format!("{}/api/auth/callback?error={}&provider=github", frontend_base.trim_end_matches('/'), code)
}

fn redirect_to(location: String) -> HttpResponse {
    HttpResponse::Found()
        .insert_header(("Location", location))
        .cookie(cleared_state_cookie())
        .finish()
}

fn failed(reason: &str) -> HttpResponse {
    eprintln!("OAuth callback: {}", reason);
    redirect_to(web_error_url(&frontend_base(), "oauth_failed"))
}

pub(crate) async fn auth_oauth_start(path: web::Path<String>) -> impl Responder {
    match normalize_oauth_provider(&path.into_inner()).as_deref() {
        Some("github") => {}
        _ => return HttpResponse::BadRequest().json(serde_json::json!({ "message": "Unsupported OAuth provider." })),
    }
    let client_id = match env::var("GITHUB_CLIENT_ID").ok().filter(|v| !v.is_empty()) {
        Some(id) => id,
        None => return failed("GITHUB_CLIENT_ID is not set"),
    };
    let state = Uuid::new_v4().to_string();
    HttpResponse::Found()
        .insert_header(("Location", github_authorize_url(&client_id, &callback_base(), &state)))
        .cookie(state_cookie(&state))
        .finish()
}

/// Le jeton d'accès GitHub de ce code.
async fn github_token(http: &reqwest::Client, code: &str) -> Result<String, String> {
    let client_id = env::var("GITHUB_CLIENT_ID").unwrap_or_default();
    let client_secret = env::var("GITHUB_CLIENT_SECRET").unwrap_or_default();
    if client_id.is_empty() || client_secret.is_empty() {
        return Err("OAuth provider not configured".to_string());
    }
    let body = serde_json::json!({
        "client_id": client_id, "client_secret": client_secret, "code": code,
        "redirect_uri": github_redirect_uri(&callback_base()),
    });
    let resp = http
        .post("https://github.com/login/oauth/access_token")
        .header("Accept", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("token exchange failed: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!("token exchange answered {}", resp.status()));
    }
    let json: serde_json::Value = resp.json().await.map_err(|_| "token response unreadable".to_string())?;
    json.get("access_token")
        .and_then(|v| v.as_str())
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .ok_or_else(|| "no access token in the token response".to_string())
}

/// L'utilisateur GitHub de ce jeton.
async fn github_user(http: &reqwest::Client, token: &str) -> Result<GithubUser, String> {
    let resp = http
        .get("https://api.github.com/user")
        .header("Authorization", format!("Bearer {}", token))
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|e| format!("user fetch failed: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!("user fetch answered {}", resp.status()));
    }
    let json: serde_json::Value = resp.json().await.map_err(|_| "user response unreadable".to_string())?;
    github_user_of(&json).ok_or_else(|| "user response without id or login".to_string())
}

pub(crate) async fn auth_oauth_callback(
    path: web::Path<String>,
    query: web::Query<OAuthCallbackQuery>,
    req: actix_web::HttpRequest,
    logic: web::Data<Arc<Logic>>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    match normalize_oauth_provider(&path.into_inner()).as_deref() {
        Some("github") => {}
        _ => return HttpResponse::BadRequest().json(serde_json::json!({ "message": "Unsupported OAuth provider." })),
    }
    if let Some(error) = query.error.as_deref() {
        eprintln!("OAuth callback: GitHub answered {}", error);
        return redirect_to(web_error_url(&frontend_base(), error));
    }
    let cookie = req.cookie(STATE_COOKIE);
    if !state_matches(query.state.as_deref(), cookie.as_ref().map(|c| c.value())) {
        return failed("state missing or different from its cookie");
    }
    let code = match query.code.as_deref().map(str::trim).filter(|c| !c.is_empty()) {
        Some(code) => code.to_string(),
        None => return failed("no authorization code"),
    };
    let http = match reqwest::Client::builder().user_agent("misfits-email-api/1.0").build() {
        Ok(http) => http,
        Err(e) => return failed(&format!("HTTP client: {}", e)),
    };
    let user = match github_token(&http, &code).await {
        Ok(token) => match github_user(&http, &token).await {
            Ok(user) => user,
            Err(e) => return failed(&e),
        },
        Err(e) => return failed(&e),
    };
    let email = account_email(&user);
    // The account exists after its first sign-in; an error here is that one.
    // Neither the address nor the error, which may hold it, is logged.
    if logic.create_user(&email, &Uuid::new_v4().to_string(), "inbox").await.is_err() {
        eprintln!("OAuth callback: account not created (it may exist already)");
    }
    let session = match open_session(mongo.get_ref().as_ref(), &email, &user.name).await {
        Ok(session) => session,
        Err(_) => return failed("the session could not be stored"),
    };
    let mut found = HttpResponse::Found();
    found.insert_header(("Location", web_session_url(&frontend_base(), &session)));
    for cookie in session_cookies(&session) {
        found.cookie(cookie);
    }
    found.cookie(cleared_state_cookie());
    found.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::session_store::{new_session, response_of};

    fn user(json: serde_json::Value) -> Option<GithubUser> {
        github_user_of(&json)
    }

    #[test]
    fn the_authorize_url_carries_the_state_and_the_encoded_callback() {
        let url = github_authorize_url("client-1", "https://mail.example.com/", "s-123");
        assert!(url.starts_with("https://github.com/login/oauth/authorize?client_id=client-1&"));
        assert!(url.contains("&redirect_uri=https%3A%2F%2Fmail.example.com%2Fapi%2Fauth%2Foauth%2Fgithub%2Fcallback&"));
        assert!(url.contains("&state=s-123&"));
        assert!(url.ends_with("&scope=user:email"));
    }

    #[test]
    fn the_state_cookie_is_http_only_on_the_oauth_routes_for_ten_minutes() {
        let cookie = state_cookie("s-123");
        assert_eq!(cookie.name(), STATE_COOKIE);
        assert_eq!(cookie.value(), "s-123");
        assert_eq!(cookie.path(), Some("/api/auth/oauth"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.secure(), Some(true));
        assert_eq!(cookie.same_site(), Some(actix_web::cookie::SameSite::Lax));
        assert_eq!(cookie.max_age(), Some(actix_web::cookie::time::Duration::seconds(600)));
        let cleared = cleared_state_cookie();
        assert_eq!(cleared.value(), "");
        assert_eq!(cleared.max_age(), Some(actix_web::cookie::time::Duration::ZERO));
    }

    #[test]
    fn a_session_is_opened_only_when_the_state_equals_its_cookie() {
        assert!(state_matches(Some("s-123"), Some("s-123")));
        assert!(!state_matches(Some("s-123"), Some("s-124")));
        assert!(!state_matches(Some("s-123"), None));
        assert!(!state_matches(None, Some("s-123")));
        assert!(!state_matches(None, None));
        assert!(!state_matches(Some(""), Some("")));
    }

    #[test]
    fn the_account_is_the_numeric_id_of_github_never_its_login() {
        let a = user(serde_json::json!({ "id": 42, "login": "octo", "name": "Octo Cat" })).unwrap();
        assert_eq!(a, GithubUser { id: 42, login: "octo".into(), name: "Octo Cat".into() });
        assert_eq!(account_email(&a), "gh42@github.oauth.misfits.ai");
        // The same login on another GitHub account is another account here.
        let b = user(serde_json::json!({ "id": 43, "login": "octo" })).unwrap();
        assert_ne!(account_email(&a), account_email(&b));
        assert_eq!(b.name, "octo");
    }

    #[test]
    fn a_github_answer_without_id_or_login_gives_no_account() {
        assert!(user(serde_json::json!({ "login": "octo" })).is_none());
        assert!(user(serde_json::json!({ "id": 0, "login": "octo" })).is_none());
        assert!(user(serde_json::json!({ "id": "42", "login": "octo" })).is_none());
        assert!(user(serde_json::json!({ "id": 42 })).is_none());
        assert!(user(serde_json::json!({ "id": 42, "login": "  " })).is_none());
        assert!(user(serde_json::json!({ "message": "Bad credentials" })).is_none());
    }

    #[test]
    fn the_web_receives_the_stored_session_in_base64_on_its_callback_route() {
        let stored = new_session("gh42@github.oauth.misfits.ai", "gh42@github.oauth.misfits.ai", "Octo", "user", Utc::now());
        let response = response_of(&stored);
        let url = web_session_url("https://mail.example.com/", &response);
        let prefix = "https://mail.example.com/api/auth/callback?session=";
        assert!(url.starts_with(prefix));
        assert!(url.ends_with("&provider=github"));
        let param = &url[prefix.len()..url.len() - "&provider=github".len()];
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(urlencoding::decode(param).unwrap().as_bytes())
            .unwrap();
        let session: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(session["access_token"], stored.session.token);
        assert_eq!(session["refresh_token"], stored.refresh_token);
        assert_eq!(session["user"]["role"], "user");
        assert_eq!(session["user"]["display_name"], "Octo");
    }

    #[test]
    fn a_failure_reaches_the_web_as_a_known_error_code() {
        assert_eq!(
            web_error_url("https://mail.example.com", "access_denied"),
            "https://mail.example.com/api/auth/callback?error=access_denied&provider=github"
        );
        assert_eq!(
            web_error_url("https://mail.example.com/", "anything<script>"),
            "https://mail.example.com/api/auth/callback?error=oauth_failed&provider=github"
        );
    }

    #[test]
    fn every_redirect_clears_the_state_cookie() {
        let response = redirect_to("https://mail.example.com/x".to_string());
        assert_eq!(response.status(), actix_web::http::StatusCode::FOUND);
        assert_eq!(response.headers().get("Location").unwrap(), "https://mail.example.com/x");
        let cookie = response.cookies().find(|c| c.name() == STATE_COOKIE).unwrap();
        assert_eq!(cookie.value(), "");
    }

    #[test]
    fn the_callback_query_reads_code_state_and_error() {
        let q = web::Query::<OAuthCallbackQuery>::from_query("code=abc&state=s-1").unwrap().into_inner();
        assert_eq!((q.code.as_deref(), q.state.as_deref(), q.error.as_deref()), (Some("abc"), Some("s-1"), None));
        let q = web::Query::<OAuthCallbackQuery>::from_query("error=access_denied&state=s-1").unwrap().into_inner();
        assert_eq!(q.error.as_deref(), Some("access_denied"));
    }
}
