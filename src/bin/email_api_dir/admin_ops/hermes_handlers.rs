#![allow(unused_imports, dead_code)]
use super::*; // inherit all imports from mod.rs

pub(crate) async fn api_hermes_chat(
    req: HttpRequest,
    body: web::Json<HermesChatProxyRequest>,
    mongo: web::Data<Arc<mongodb::Client>>,
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

    let started = std::time::Instant::now();
    let client = reqwest::Client::new();
    let response = match client
        .post(url)
        .bearer_auth(api_key)
        .header("X-Hermes-Session-Id", session_id.clone())
        .header("X-Hermes-Session-Key", session_key)
        .json(&payload)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Hermes upstream request error: {}", e);
            log_llm_usage_event(
                mongo.get_ref(),
                LlmUsageEvent {
                    feature: "hermes_chat_proxy".to_string(),
                    status: "failed".to_string(),
                    model: model.clone(),
                    prompt_tokens: 0,
                    completion_tokens: 0,
                    total_tokens: 0,
                    latency_ms: Some(i64::try_from(started.elapsed().as_millis()).unwrap_or(0)),
                    session_id: Some(session_id.clone()),
                    user_id: Some(user_id.clone()),
                    source_id: None,
                    source_url: None,
                    error: Some(format!("request_error: {}", e)),
                },
            )
            .await;
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
            log_llm_usage_event(
                mongo.get_ref(),
                LlmUsageEvent {
                    feature: "hermes_chat_proxy".to_string(),
                    status: "failed".to_string(),
                    model: model.clone(),
                    prompt_tokens: 0,
                    completion_tokens: 0,
                    total_tokens: 0,
                    latency_ms: Some(i64::try_from(started.elapsed().as_millis()).unwrap_or(0)),
                    session_id: Some(session_id.clone()),
                    user_id: Some(user_id.clone()),
                    source_id: None,
                    source_url: None,
                    error: Some(format!("invalid_json: {}", e)),
                },
            )
            .await;
            return HttpResponse::BadGateway().json(serde_json::json!({
                "error": "Invalid Hermes upstream response"
            }));
        }
    };

    let (prompt_tokens, completion_tokens, total_tokens) = extract_llm_usage_tokens(&body_json);
    log_llm_usage_event(
        mongo.get_ref(),
        LlmUsageEvent {
            feature: "hermes_chat_proxy".to_string(),
            status: if status.is_success() {
                "completed".to_string()
            } else {
                "failed".to_string()
            },
            model: model.clone(),
            prompt_tokens,
            completion_tokens,
            total_tokens,
            latency_ms: Some(i64::try_from(started.elapsed().as_millis()).unwrap_or(0)),
            session_id: Some(session_id.clone()),
            user_id: Some(user_id.clone()),
            source_id: None,
            source_url: None,
            error: body_json
                .get("error")
                .and_then(|v| v.get("message"))
                .and_then(|v| v.as_str())
                .map(|v| v.to_string()),
        },
    )
    .await;

    HttpResponse::build(
        actix_web::http::StatusCode::from_u16(status.as_u16())
            .unwrap_or(actix_web::http::StatusCode::BAD_GATEWAY),
    )
    .json(body_json)
}

pub(crate) async fn api_hermes_runs_list(
    query: web::Query<HermesRunsListQuery>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let limit = query.limit.unwrap_or(40).clamp(10, 200);

    match load_ai_activity_runs(mongo.get_ref(), limit).await {
        Ok(runs) if !runs.is_empty() => {
            return HttpResponse::Ok().json(serde_json::json!({ "data": runs }));
        }
        Ok(_) => {}
        Err(e) => eprintln!("api_hermes_runs_list local usage read error: {}", e),
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

    let url = format!("{}/v1/runs?limit={}", base, limit);
    let client = reqwest::Client::new();
    let response = match client.get(url).bearer_auth(api_key).send().await {
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

pub(crate) async fn api_hermes_runs(
    req: HttpRequest,
    body: web::Json<HermesRunsProxyRequest>,
) -> impl Responder {
    let input = match body.input.clone().filter(|v| !v.is_null()) {
        Some(v) => v,
        None => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "input is required"
            }))
        }
    };

    let base = resolve_hermes_base_url();
    let api_key = match env::var("HERMES_API_KEY") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "HERMES_API_KEY is not configured"
            }))
        }
    };

    let url = format!("{}/v1/runs", base);
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

    let payload = serde_json::json!({
        "model": model,
        "input": input,
    });

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
