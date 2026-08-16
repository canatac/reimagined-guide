#![allow(unused_imports, dead_code)]
use super::super::*;

pub(crate) async fn api_hermes_chat(
    req: HttpRequest,
    body: web::Json<HermesChatProxyRequest>,
) -> impl Responder {
    if body.messages.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "messages is required"
        }));
    }

    let base = resolve_hermes_base_url();
    let api_key = match env::var("HERMES_API_KEY") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "HERMES_API_KEY is not configured"
            }))
        }
    };

    let url = format!("{}/v1/chat/completions", base);
    let model = body
        .model
        .clone()
        .unwrap_or_else(|| env::var("HERMES_MODEL").unwrap_or_else(|_| "hermes-agent".to_string()));

    let thread_id = body
        .thread_id
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    let fallback_user_id = resolve_user_id(&req);
    let user_id = body
        .user_id
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(fallback_user_id);

    let session_id = body
        .session_id
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("mail-thread-{}", thread_id));

    let session_key = body
        .session_key
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("user-{}", user_id));

    let mut payload = serde_json::json!({
        "model": model,
        "messages": body.messages,
    });

    if let Some(temp) = body.temperature {
        payload["temperature"] = serde_json::json!(temp);
    }
    if let Some(max_tokens) = body.max_tokens {
        payload["max_tokens"] = serde_json::json!(max_tokens);
    }

    let client = reqwest::Client::new();
    let response = match client
        .post(url)
        .bearer_auth(api_key)
        .header("X-Hermes-Session-Id", session_id)
        .header("X-Hermes-Session-Key", session_key)
        .json(&payload)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Hermes upstream request error: {}", e);
            return HttpResponse::BadGateway().json(serde_json::json!({
                "error": "Hermes upstream unavailable"
            }));
        }
    };

    let status = response.status();
    let body_json = match response.json::<serde_json::Value>().await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Hermes upstream JSON parse error: {}", e);
            return HttpResponse::BadGateway().json(serde_json::json!({
                "error": "Invalid Hermes upstream response"
            }));
        }
    };

    HttpResponse::build(
        actix_web::http::StatusCode::from_u16(status.as_u16())
            .unwrap_or(actix_web::http::StatusCode::BAD_GATEWAY),
    )
    .json(body_json)
}
