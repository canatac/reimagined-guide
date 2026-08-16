// oauth.rs — Handlers OAuth (start + callback). Extraits de auth_handlers.rs.
#![allow(unused_imports, dead_code)]
use super::super::*;
use super::session::make_session;

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
